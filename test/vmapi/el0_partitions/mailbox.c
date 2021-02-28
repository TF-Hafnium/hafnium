/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Causes secondary VM to send two messages to primary VM. The second message
 * will reach the mailbox while it's not writable. Checks that notifications are
 * properly delivered when mailbox is cleared.
 */
TEST(mailbox, primary_to_secondary)
{
	char message[] = "not ready echo";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "echo_with_notification", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/* Send a message to echo service, and get response back. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_EQ(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		FFA_SUCCESS_32);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_msg_send_size(run_res), sizeof(message));
	EXPECT_EQ(memcmp(mb.recv, message, sizeof(message)), 0);

	/* Let secondary VM continue running so that it will wait again. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/* Without clearing our mailbox, send message again. */
	reverse(message, strnlen_s(message, sizeof(message)));
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));

	/* Message should be dropped since the mailbox was not cleared. */
	EXPECT_EQ(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		FFA_SUCCESS_32);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/* Clear the mailbox. We expect to be told there are pending waiters. */
	EXPECT_EQ(ffa_rx_release().func, FFA_RX_RELEASE_32);

	/* Retrieve a single waiter. */
	EXPECT_EQ(hf_mailbox_waiter_get(HF_PRIMARY_VM_ID), SERVICE_VM1);
	EXPECT_EQ(hf_mailbox_waiter_get(HF_PRIMARY_VM_ID), -1);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_msg_send_size(run_res), sizeof(message));
	EXPECT_EQ(memcmp(mb.recv, message, sizeof(message)), 0);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}
