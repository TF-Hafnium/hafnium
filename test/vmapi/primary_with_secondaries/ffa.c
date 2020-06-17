/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include <stdint.h>

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Send a message to a secondary VM which checks the validity of the received
 * header.
 */
TEST(ffa, msg_send)
{
	const char message[] = "ffa_msg_send";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_check", mb.send);

	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_EQ(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		FFA_SUCCESS_32);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Send a message to a secondary VM spoofing the source VM id.
 */
TEST(ffa, msg_send_spoof)
{
	const char message[] = "ffa_msg_send";
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_check", mb.send);

	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_FFA_ERROR(
		ffa_msg_send(SERVICE_VM2, SERVICE_VM1, sizeof(message), 0),
		FFA_INVALID_PARAMETERS);
}

/**
 * Send a message to a secondary VM with incorrect destination id.
 */
TEST(ffa, ffa_invalid_destination_id)
{
	const char message[] = "fail to send";
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_check", mb.send);
	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_FFA_ERROR(ffa_msg_send(HF_PRIMARY_VM_ID, -1, sizeof(message), 0),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Ensure that the length parameter is respected when sending messages.
 */
TEST(ffa, ffa_incorrect_length)
{
	const char message[] = "this should be truncated";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_length", mb.send);

	/* Send the message and compare if truncated. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	/* Hard code incorrect length. */
	EXPECT_EQ(ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 16, 0).func,
		  FFA_SUCCESS_32);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Attempt to send a message larger than what is supported.
 */
TEST(ffa, ffa_large_message)
{
	const char message[] = "fail to send";
	struct mailbox_buffers mb = set_up_mailbox();

	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	/* Send a message that is larger than the mailbox supports (4KB). */
	EXPECT_FFA_ERROR(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 4 * 1024 + 1, 0),
		FFA_INVALID_PARAMETERS);
}

/**
 * Verify secondary VM non blocking recv.
 */
TEST(ffa, ffa_recv_non_blocking)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value run_res;

	/* Check is performed in secondary VM. */
	SERVICE_SELECT(SERVICE_VM1, "ffa_recv_non_blocking", mb.send);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}
