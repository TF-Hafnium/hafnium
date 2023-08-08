/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEST_SERVICE(ffa_direct_message_resp_echo)
{
	struct ffa_value args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_yield_direct_message_resp_echo)
{
	struct ffa_value args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	/*
	 * Give back control to VM/SP, that sent the direct request message,
	 * through FFA_YIELD ABI and specify timeout of 0x123456789.
	 */
	ffa_yield_timeout(0x1, 0x23456789);

	/* Send the echo through direct message response. */
	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_message_echo_services)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	ffa_id_t target_id;

	/* Retrieve FF-A ID of the target endpoint. */
	receive_indirect_message((void *)&target_id, sizeof(target_id),
				 recv_buf, NULL);

	HFTEST_LOG("Echo test with: %x", target_id);

	res = ffa_msg_send_direct_req(hf_vm_get_id(), target_id, msg[0], msg[1],
				      msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);

	ffa_yield();
}

TEST_SERVICE(ffa_yield_direct_message_echo_services)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	ffa_id_t target_id;

	/* Retrieve FF-A ID of the target endpoint. */
	receive_indirect_message((void *)&target_id, sizeof(target_id),
				 recv_buf, NULL);

	HFTEST_LOG("Echo test with: %x", target_id);

	res = ffa_msg_send_direct_req(hf_vm_get_id(), target_id, msg[0], msg[1],
				      msg[2], msg[3], msg[4]);

	/*
	 * Be prepared to allocate CPU cycles to target vCPU if it yields while
	 * processing direct message.
	 */
	while (res.func == FFA_YIELD_32) {
		/* VM id/vCPU index are passed through arg1. */
		EXPECT_EQ(res.arg1, ffa_vm_vcpu(target_id, 0));

		/* Allocate CPU cycles to resume SP. */
		res = ffa_run(target_id, 0);
	}
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);

	ffa_yield();
}

TEST_SERVICE(ffa_direct_msg_req_disallowed_smc)
{
	struct ffa_value args = ffa_msg_wait();
	struct ffa_value ret;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service1_info = service1(recv_buf);

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ret = ffa_msg_wait();
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	ret = ffa_msg_send_direct_req(service1_info->vm_id, ffa_sender(args), 0,
				      0, 0, 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

/**
 * Verify that services can't send direct message requests
 * when invoked by FFA_RUN.
 */
TEST_SERVICE(ffa_disallowed_direct_msg_req)
{
	struct ffa_value args;
	struct ffa_value ret;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service1_info = service1(recv_buf);

	ret = ffa_msg_send_direct_req(service1_info->vm_id, HF_PRIMARY_VM_ID, 0,
				      0, 0, 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	ret = ffa_msg_send_direct_req(service1_info->vm_id, HF_VM_ID_BASE + 10,
				      0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

/**
 * Verify a service can't send a direct message response when it hasn't
 * first been sent a request.
 */
TEST_SERVICE(ffa_disallowed_direct_msg_resp)
{
	struct ffa_value args;
	struct ffa_value ret;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service1_info = service1(recv_buf);

	ret = ffa_msg_send_direct_resp(service1_info->vm_id, HF_PRIMARY_VM_ID,
				       0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

/**
 * Verify a service can't send a response to a different VM than the one
 * that sent the request.
 * Verify a service cannot send a response with a sender ID different from
 * its own service ID.
 */
TEST_SERVICE(ffa_direct_msg_resp_invalid_sender_receiver)
{
	struct ffa_value res;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	ffa_id_t invalid_receiver;
	struct ffa_value args = ffa_msg_wait();
	ffa_id_t own_id = hf_vm_get_id();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_id_t sender = ffa_sender(args);
	ASSERT_EQ(own_id, ffa_receiver(args));

	/* Other receiver ID. */
	invalid_receiver = ffa_is_vm_id(own_id) ? service2_info->vm_id : own_id;
	res = ffa_msg_send_direct_resp(own_id, invalid_receiver, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	/* Spoof sender ID. */
	res = ffa_msg_send_direct_resp(service2_info->vm_id, sender, 0, 0, 0, 0,
				       0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp(own_id, sender, 0, 0, 0, 0, 0);

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_message_cycle_denied)
{
	struct ffa_value res;
	struct ffa_value args = ffa_msg_wait();
	ffa_id_t sender;
	ffa_id_t receiver;
	ffa_id_t own_id = hf_vm_get_id();

	ASSERT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);
	receiver = ffa_receiver(args);
	sender = ffa_sender(args);

	EXPECT_EQ(receiver, hf_vm_get_id());

	res = ffa_msg_send_direct_req(own_id, sender, 1, 2, 3, 4, 5);
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}
