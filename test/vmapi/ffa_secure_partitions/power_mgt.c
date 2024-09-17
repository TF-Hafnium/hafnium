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

struct pwr_mgt_cpu_entry_args {
	ffa_id_t receiver_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_vcpu_index_t vcpu_id;
	struct spinlock lock;
};

/**
 * Performs direct request echo test in the running CPU.
 */
static void cpu_entry_echo(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
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

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

static void cpu_entry_echo_second_sp(uintptr_t arg)
{
	struct pwr_mgt_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct pwr_mgt_cpu_entry_args *)arg;
	struct ffa_value res;
	ffa_vcpu_index_t vcpu_id = args->vcpu_count == 1 ? 0 : args->vcpu_id;

	/*
	 * Second SP needs FFA_RUN before communicating with it.
	 * TODO: the FFA_RUN ABI only needs to be called for the MP UP endpoints
	 * to bootstrap the EC in the current core. Though there is an issue
	 * with the current FFA_RUN implementation: it returns back to the
	 * caller with FFA_MSG_WAIT interface, without resuming the target
	 * SP. When fixing the FFA_RUN issue, this bit of code needs addressing.
	 */
	res = ffa_run(args->receiver_id, vcpu_id);
	EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

	cpu_entry_echo(arg);
}

/**
 * Validates that the core index passed, matches the vMPDIR set by the SPMC.
 */
static void cpu_entry_check_cpu_idx(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct pwr_mgt_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct pwr_mgt_cpu_entry_args *)arg;
	struct ffa_value res;

	/*
	 * For S-EL1 MP partitions, the linear cpu index is expected to match
	 * the vCPU ID.
	 */
	res = sp_check_cpu_idx_cmd_send(own_id, args->receiver_id,
					args->vcpu_id);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

static void cpu_entry_check_cpu_idx_second_sp(uintptr_t arg)
{
	struct pwr_mgt_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct pwr_mgt_cpu_entry_args *)arg;
	struct ffa_value res;

	/*
	 * Make the receiver VM reach the message loop in the respective EC.
	 * This function is meant to be used if the receiver is an MP FF-A
	 * endpoint.
	 */
	res = ffa_run(args->receiver_id, args->vcpu_id);
	EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

	cpu_entry_check_cpu_idx(arg);
}

static void base_cpu_start_test(struct ffa_uuid recv_uuid,
				void (*entry)(uintptr_t arg),
				bool skip_if_up_sp)
{
	struct pwr_mgt_cpu_entry_args args = {.lock = SPINLOCK_INIT};
	struct ffa_partition_info receiver;
	struct mailbox_buffers mb = set_up_mailbox();

	EXPECT_EQ(get_ffa_partition_info(recv_uuid, &receiver, 1, mb.recv), 1);

	args.receiver_id = receiver.vm_id;
	args.vcpu_count = receiver.vcpu_count;

	if (args.vcpu_count == 1 && skip_if_up_sp) {
		HFTEST_LOG("Skipping test as receiver is UP SP.\n");
		return;
	}

	/* Start secondary EC while holding lock. */
	sl_lock(&args.lock);

	for (size_t i = 1; i < MAX_CPUS - 1; i++) {
		HFTEST_LOG("Booting CPU %zu", i);

		/*
		 * If receiver is an S-EL0 partition it is expected to have one
		 * execution context. If it is S-EL1 partition can have MAX_CPUS
		 * or 1.
		 */
		args.vcpu_id = (ffa_vcpu_index_t)i;

		EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(i),
					   hftest_get_secondary_ec_stack(i),
					   entry, (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&args.lock);

		HFTEST_LOG("Done with CPU %zu", i);
	}
}

TEST(ffa_power_mgt, cpu_start_echo_second_sp)
{
	/* Second SP can be either S-EL0 or S-EL1 SP. */
	base_cpu_start_test((struct ffa_uuid){SP_SERVICE_SECOND_UUID},
			    cpu_entry_echo_second_sp, false);
}

TEST(ffa_power_mgt, cpu_start_echo_first_sp)
{
	base_cpu_start_test((struct ffa_uuid){SP_SERVICE_FIRST_UUID},
			    cpu_entry_echo, false);
}

TEST(ffa_power_mgt, cpu_start_core_idx_second_sp)
{
	/* Test to be skipped for S-EL0 partition. */
	base_cpu_start_test((struct ffa_uuid){SP_SERVICE_SECOND_UUID},
			    cpu_entry_check_cpu_idx_second_sp, true);
}

TEST(ffa_power_mgt, cpu_start_core_idx_first_sp)
{
	/* Test to be skipped for S-EL0 partition. */
	base_cpu_start_test((struct ffa_uuid){SP_SERVICE_FIRST_UUID},
			    cpu_entry_check_cpu_idx, true);
}
