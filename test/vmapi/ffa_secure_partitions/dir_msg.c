/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/delay.h"
#include "hf/arch/vm/power_mgmt.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define SP_SLEEP_LONG 2000U

struct secondary_cpu_entry_args {
	ffa_id_t receiver_id;
	ffa_vcpu_count_t vcpu_count;
};

/**
 * Communicates with partition via direct messaging to validate functioning of
 * direct request/response interfaces.
 */
TEST(ffa_msg_send_direct_req, succeeds_nwd_to_sp_echo)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
			       msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
}

/**
 * Validate SP to SP direct messaging is functioning as expected.
 */
TEST(ffa_msg_send_direct_req, succeeds_sp_to_sp_echo)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_req_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
				   msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

/**
 * Test that if a direct message request is sent to an SP that is already
 * waiting for a direct message response an FFA_BUSY error code is returned.
 */
TEST(ffa_msg_send_direct_req, fails_direct_req_to_waiting_sp)
{
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_req_echo_busy_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

/**
 * Test various state transitions requested by an SP under RTM_FFA_DIR_REQ
 * partition runtime model
 */
TEST(partition_runtime_model, rtm_ffa_dir_req)
{
	const ffa_id_t receiver_id = SP_ID(1);
	const ffa_id_t companion_sp_id = SP_ID(2);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_check_state_transitions_cmd_send(own_id, receiver_id,
						  companion_sp_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

static void migrate_busy_up_sp(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;
	const uint32_t msg[] = {SP_ECHO_CMD, 0x1, 0x2, 0x3, 0x4};
	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;

	/*
	 * Wait till the primary VM on boot CPU has established the
	 * call chain with receiver SP.
	 */
	waitms(200);

	/*
	 * A direct request message cannot be serviced by the receiver SP
	 * since it is in a BLOCKED state on a boot CPU.
	 */
	res = sp_echo_cmd_send(own_id, args->receiver_id, msg[0], msg[1],
			       msg[2], msg[3]);

	EXPECT_EQ(ffa_func_id(res), FFA_ERROR_32);

	/*
	 * An attempt to migrate the UP SP from boot CPU to current CPU using
	 * FFA_RUN interface should fail.
	 */
	res = ffa_run(args->receiver_id, 0);

	EXPECT_EQ(ffa_func_id(res), FFA_ERROR_32);

	arch_cpu_stop();
}

/**
 * Test to make sure the vCPU of an UP SP cannot be migrated from current CPU
 * to a different physical CPU while the vCPU is in BLOCKED state as part of an
 * SP call chain.
 */
TEST_PRECONDITION_LONG_RUNNING(ffa_call_chain, disallow_migration_blocked_sp,
			       service2_is_up_sp)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct secondary_cpu_entry_args args;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *receiver_info = service2(mb.recv);
	struct ffa_partition_info *companion_info = service1(mb.recv);
	ffa_id_t receiver_id = receiver_info->vm_id;
	ffa_id_t companion_id = companion_info->vm_id;

	args.receiver_id = receiver_id;
	args.vcpu_count = receiver_info->vcpu_count;

	for (size_t i = 1; i < MAX_CPUS; i++) {
		uintptr_t id;

		id = hftest_get_cpu_id(i);
		HFTEST_LOG("Booting CPU %zu - %lx", i, id);

		EXPECT_EQ(
			hftest_cpu_start(id, hftest_get_secondary_ec_stack(i),
					 migrate_busy_up_sp, (uintptr_t)&args),
			true);

		HFTEST_LOG("Done with CPU %zu", i);
	}

	/*
	 * Send command to receiver SP to send command to companion SP to sleep
	 * there by putting receiver SP in BLOCKED state.
	 */
	res = sp_fwd_sleep_cmd_send(own_id, receiver_id, companion_id,
				    SP_SLEEP_LONG, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}
