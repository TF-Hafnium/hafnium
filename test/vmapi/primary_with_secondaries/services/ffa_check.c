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
	EXPECT_EQ(ffa_msg_send_receiver(ret), hf_vm_get_id());
	EXPECT_EQ(ffa_msg_send_sender(ret), HF_PRIMARY_VM_ID);

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

TEST_SERVICE(ffa_direct_message_resp_echo)
{
	struct ffa_value args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_msg_send_receiver(args),
				 ffa_msg_send_sender(args), args.arg3,
				 args.arg4, args.arg5, args.arg6, args.arg7);
}

TEST_SERVICE(ffa_direct_msg_req_disallowed_smc)
{
	struct ffa_value args = ffa_msg_wait();
	struct ffa_value ret;

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ret = ffa_yield();
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	ret = ffa_msg_send(ffa_msg_send_receiver(args),
			   ffa_msg_send_sender(args), 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	ret = ffa_msg_wait();
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	ret = ffa_msg_send_direct_req(SERVICE_VM1, SERVICE_VM2, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	ret = ffa_msg_poll();
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	ffa_msg_send_direct_resp(ffa_msg_send_receiver(args),
				 ffa_msg_send_sender(args), args.arg3,
				 args.arg4, args.arg5, args.arg6, args.arg7);
}

/**
 * Verify that secondary VMs can't send direct message requests
 * when invoked by FFA_RUN.
 */
TEST_SERVICE(ffa_disallowed_direct_msg_req)
{
	struct ffa_value args;
	struct ffa_value ret;

	ret = ffa_msg_send_direct_req(SERVICE_VM1, HF_PRIMARY_VM_ID, 0, 0, 0, 0,
				      0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	ret = ffa_msg_send_direct_req(SERVICE_VM1, SERVICE_VM2, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_msg_send_receiver(args),
				 ffa_msg_send_sender(args), args.arg3,
				 args.arg4, args.arg5, args.arg6, args.arg7);
}

/**
 * Verify a secondary VM can't send a direct message response when it hasn't
 * first been sent a request.
 */
TEST_SERVICE(ffa_disallowed_direct_msg_resp)
{
	struct ffa_value args;
	struct ffa_value ret;

	ret = ffa_msg_send_direct_resp(SERVICE_VM1, HF_PRIMARY_VM_ID, 0, 0, 0,
				       0, 0);
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_msg_send_receiver(args),
				 ffa_msg_send_sender(args), args.arg3,
				 args.arg4, args.arg5, args.arg6, args.arg7);
}

/**
 * Verify a secondary VM can't send a response to a different VM than the one
 * that sent the request.
 * Verify a secondary VM cannot send a response with a sender ID different from
 * its own secondary VM ID.
 */
TEST_SERVICE(ffa_direct_msg_resp_invalid_sender_receiver)
{
	struct ffa_value args = ffa_msg_wait();
	struct ffa_value res;

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_vm_id_t sender = ffa_msg_send_sender(args);
	ffa_vm_id_t receiver = ffa_msg_send_receiver(args);

	res = ffa_msg_send_direct_resp(receiver, SERVICE_VM2, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	res = ffa_msg_send_direct_resp(SERVICE_VM2, sender, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp(receiver, sender, 0, 0, 0, 0, 0);
}

/**
 * Secondary VM waits for a direct message request but primary VM
 * calls ffa_run instead. Verify the secondary VM does not run.
 */
TEST_SERVICE(ffa_direct_msg_run)
{
	struct ffa_value res = ffa_msg_wait();

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	res = ffa_msg_send_direct_resp(ffa_msg_send_receiver(res),
				       ffa_msg_send_sender(res), 2, 0, 0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 3);

	ffa_msg_send_direct_resp(ffa_msg_send_receiver(res),
				 ffa_msg_send_sender(res), 4, 0, 0, 0, 0);
}
