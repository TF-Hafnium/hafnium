/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEST_SERVICE(ffa_check)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	const char message[] = "ffa_msg_send";

	/* Wait for single message to be sent by the primary VM. */
	struct ffa_value ret = ffa_msg_wait();

	EXPECT_EQ(ret.func, FFA_MSG_SEND_32);

	/* Ensure message header has all fields correctly set. */
	EXPECT_EQ(ffa_msg_send_size(ret), sizeof(message));
	EXPECT_EQ(ffa_receiver(ret), hf_vm_get_id());
	EXPECT_EQ(ffa_sender(ret), HF_PRIMARY_VM_ID);

	/* Ensure that the payload was correctly transmitted. */
	EXPECT_EQ(memcmp(recv_buf, message, sizeof(message)), 0);

	ffa_yield();
}

TEST_SERVICE(ffa_length)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	const char message[] = "this should be truncated";

	/* Wait for single message to be sent by the primary VM. */
	struct ffa_value ret = ffa_msg_wait();

	EXPECT_EQ(ret.func, FFA_MSG_SEND_32);

	/* Verify the length is as expected. */
	EXPECT_EQ(16, ffa_msg_send_size(ret));

	/* Check only part of the message is sent correctly. */
	EXPECT_NE(memcmp(recv_buf, message, sizeof(message)), 0);
	EXPECT_EQ(memcmp(recv_buf, message, ffa_msg_send_size(ret)), 0);

	ffa_yield();
}

TEST_SERVICE(ffa_recv_non_blocking)
{
	/* Wait for single message to be sent by the primary VM. */
	struct ffa_value ret = ffa_msg_poll();

	EXPECT_FFA_ERROR(ret, FFA_RETRY);

	ffa_yield();
}

/**
 * Service for indirect message error checking.
 * The VM unmap its RX/TX and waits for a message.
 */
TEST_SERVICE(ffa_indirect_msg_error)
{
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);

	ffa_msg_wait();
}

/**
 * Service waits for a direct message request but primary VM
 * calls ffa_run instead. Verify the service does not run.
 */
TEST_SERVICE(ffa_direct_msg_run)
{
	struct ffa_value res = ffa_msg_wait();

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	res = ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0,
				       0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 3);

	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 4, 0, 0, 0,
				 0);
}
