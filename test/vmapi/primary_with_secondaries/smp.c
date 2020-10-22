/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(smp)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Run a service that starts a second vCPU, and check that both the first and
 * second vCPU send messages to us.
 */
TEST(smp, two_vcpus)
{
	const char expected_response_0[] = "vCPU 0";
	const char expected_response_1[] = "vCPU 1";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM3, "smp", mb.send);

	/* Let the first vCPU start the second vCPU. */
	run_res = ffa_run(SERVICE_VM3, 0);
	EXPECT_EQ(run_res.func, FFA_INTERRUPT_32);
	EXPECT_EQ(ffa_vm_id(run_res), SERVICE_VM3);
	EXPECT_EQ(ffa_vcpu_index(run_res), 1);

	/* Run the second vCPU and wait for a message. */
	dlog("Run second vCPU for message\n");
	run_res = ffa_run(SERVICE_VM3, 1);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_msg_send_size(run_res), sizeof(expected_response_1));
	EXPECT_EQ(memcmp(mb.recv, expected_response_1,
			 sizeof(expected_response_1)),
		  0);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Run the first vCPU and wait for a different message. */
	dlog("Run first vCPU for message\n");
	run_res = ffa_run(SERVICE_VM3, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_msg_send_size(run_res), sizeof(expected_response_0));
	EXPECT_EQ(memcmp(mb.recv, expected_response_0,
			 sizeof(expected_response_0)),
		  0);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Run the second vCPU again, and expect it to turn itself off. */
	dlog("Run second vCPU for poweroff.\n");
	run_res = ffa_run(SERVICE_VM3, 1);
	EXPECT_EQ(run_res.func, HF_FFA_RUN_WAIT_FOR_INTERRUPT);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);
}
