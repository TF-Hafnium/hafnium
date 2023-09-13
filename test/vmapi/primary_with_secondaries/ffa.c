/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include <stdint.h>

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Verify that FFA_MSG_WAIT responds correctly to wrong parameters.
 */
TEST(ffa, ffa_msg_wait_fail)
{
	struct ffa_value ret;
	ret = ffa_call((struct ffa_value){.func = FFA_MSG_WAIT_32,
					  .arg1 = 1,
					  .arg2 = 2,
					  .arg3 = 3,
					  .arg4 = 4,
					  .arg5 = 5,
					  .arg6 = 6,
					  .arg7 = 7});
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

/**
 * Verify that partition discovery via the FFA_PARTITION_INFO interface
 * returns the expected information on the VMs in the system.
 */
TEST(ffa, ffa_partition_info)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;
	const struct ffa_partition_info *partitions = mb.recv;
	struct ffa_uuid uuid;
	ffa_vm_count_t vm_count;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	vm_count = ret.arg2;
	EXPECT_EQ(vm_count, 4);

	for (uint16_t index = 0; index < vm_count; ++index) {
		ffa_id_t vm_id = partitions[index].vm_id;
		EXPECT_GE(vm_id, (ffa_id_t)HF_PRIMARY_VM_ID);
		EXPECT_LE(vm_id, (ffa_id_t)SERVICE_VM3);

		/*
		 * NOTE: The ordering is NOT specified by the spec, but is an
		 * artifact of how it's implemented in Hafnium. If that changes
		 * the following EXPECT could fail.
		 */
		EXPECT_EQ(vm_id, index + 1);

		EXPECT_GE(partitions[index].vcpu_count, 1);
	}

	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Trying to run a partition which is waiting for a message should not actually
 * run it, but return FFA_MSG_WAIT again.
 */
TEST(ffa, run_waiting)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value run_res;

	SERVICE_SELECT(SERVICE_VM1, "run_waiting", mb.send);

	/* Let the secondary get started and wait for a message. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/*
	 * Trying to run it again should return the same value, and not actually
	 * run it.
	 */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);
}

/*
 * The secondary vCPU is waiting for a direct request, but the primary instead
 * calls `FFA_RUN`. This should return immediately to the primary without the
 * secondary ever actually being run.
 */
TEST(ffa, ffa_secondary_run)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_direct_msg_run", mb.send);
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 2);

	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 3, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 4);
}
