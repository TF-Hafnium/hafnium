/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/spinlock.h"

#include "vmapi/hf/call.h"

#include "ffa_endpoints.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

alignas(4096) static uint8_t secondary_ec_stack[MAX_CPUS - 1][4096];

struct pwr_mgt_cpu_entry_args {
	ffa_vm_id_t receiver_id;
	ffa_vcpu_index_t vcpu_id;
	struct spinlock lock;
};

/**
 * Releases the lock passed in.
 */
static void cpu_entry_echo(uintptr_t arg)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	const uint32_t msg[] = {SP_ECHO_CMD, 0x1, 0x2, 0x3, 0x4};
	struct pwr_mgt_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct pwr_mgt_cpu_entry_args *)arg;
	struct ffa_value res;

	res = sp_echo_cmd_send(own_id, args->receiver_id, msg[0], msg[1],
			       msg[2], msg[3]);

	EXPECT_EQ(ffa_func_id(res), FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);

	sl_unlock(&args->lock);

	arch_cpu_stop();
}

static void cpu_entry_echo_second_sp(uintptr_t arg)
{
	struct pwr_mgt_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct pwr_mgt_cpu_entry_args *)arg;
	struct ffa_value res;

	/*
	 * Second SP needs FFA_RUN before communicating with it.
	 * TODO: the FFA_RUN ABI only needs to be called for the MP UP endpoints
	 * to bootstrap the EC in the current core. Though there is an issue
	 * with the current FFA_RUN implementation: it returns back to the
	 * caller with FFA_MSG_WAIT interface, without resuming the target
	 * SP. When fixing the FFA_RUN issue, this bit of code needs addressing.
	 */
	res = ffa_run(args->receiver_id, args->vcpu_id);
	EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

	cpu_entry_echo(arg);
}

static void base_cpu_start_test(struct ffa_uuid *recv_uuid,
				void (*entry)(uintptr_t arg))
{
	struct pwr_mgt_cpu_entry_args args = {.lock = SPINLOCK_INIT};
	struct ffa_partition_info receiver;

	EXPECT_EQ(get_ffa_partition_info(recv_uuid, &receiver, 1), 1);

	args.receiver_id = receiver.vm_id;

	/* Start secondary EC while holding lock. */
	sl_lock(&args.lock);

	for (size_t i = 1; i < MAX_CPUS - 1; i++) {
		size_t hftest_cpu_index = MAX_CPUS - i;
		HFTEST_LOG("Booting CPU %u", i);

		/*
		 * If receiver is an S-EL0 partition it is expected to have one
		 * execution context. If it is S-EL1 partition can have MAX_CPUS
		 * or 1.
		 */
		args.vcpu_id =
			(receiver.vcpu_count == 1) ? 0 : (ffa_vcpu_index_t)i;

		EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(hftest_cpu_index),
					   secondary_ec_stack[i - 1],
					   sizeof(secondary_ec_stack[0]), entry,
					   (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&args.lock);

		HFTEST_LOG("Done with CPU %u", i);
	}
}

TEST(ffa_power_mgt, cpu_start_second_sp)
{
	/* Second SP can be either S-EL0 or S-EL1 SP. */
	base_cpu_start_test(&(struct ffa_uuid){SP_SERVICE_SECOND_UUID},
			    cpu_entry_echo_second_sp);
}

TEST(ffa_power_mgt, cpu_start_first_sp)
{
	base_cpu_start_test(&(struct ffa_uuid){SP_SERVICE_FIRST_UUID},
			    cpu_entry_echo);
}
