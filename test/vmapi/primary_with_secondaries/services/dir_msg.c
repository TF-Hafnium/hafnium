/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/check.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define MAX_RESP_REGS (MAX_MSG_SIZE / sizeof(uint64_t))

static uint16_t get_uuid_count(struct hftest_context *ctx)
{
	if (ctx->is_ffa_manifest_parsed) {
		return ctx->partition_manifest.uuid_count;
	}

	return 0;
}

static struct ffa_uuid *get_uuids(struct hftest_context *ctx)
{
	if (ctx->is_ffa_manifest_parsed) {
		return (struct ffa_uuid *)&ctx->partition_manifest.uuids;
	}

	return NULL;
}

static bool is_uuid_in_list(uint16_t uuid_count, struct ffa_uuid target_uuid,
			    struct ffa_uuid *uuid_list)
{
	uint16_t i;

	/* Allow for nil uuid usage. */
	if (ffa_uuid_is_null(&target_uuid)) {
		return true;
	}

	for (i = 0; i < uuid_count; i++) {
		if (ffa_uuid_is_null(&target_uuid)) {
			break;
		}
		if (ffa_uuid_equal(&uuid_list[i], &target_uuid)) {
			return true;
		}
	}

	return false;
}

TEST_SERVICE(ffa_direct_message_resp_echo)
{
	struct ffa_value args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_message_req2_resp_echo)
{
	uint64_t msg[MAX_RESP_REGS];
	struct ffa_value res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &res.arg4,
		 MAX_RESP_REGS * sizeof(uint64_t));

	ffa_msg_send_direct_resp2(ffa_receiver(res), ffa_sender(res),
				  (const uint64_t *)msg, MAX_RESP_REGS);

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

TEST_SERVICE(ffa_yield_direct_message_resp2_echo)
{
	struct ffa_value res = ffa_msg_wait();
	uint64_t msg[MAX_RESP_REGS] = {0};

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	/*
	 * Give back control to VM/SP, that sent the direct request message,
	 * through FFA_YIELD ABI and specify timeout of 0x123456789.
	 */
	ffa_yield_timeout(0x1, 0x23456789);

	HFTEST_LOG("after yield");

	/* Send the echo through direct message response. */
	memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &res.arg4,
		 MAX_RESP_REGS * sizeof(uint64_t));

	ffa_msg_send_direct_resp2(ffa_receiver(res), ffa_sender(res),
				  (const uint64_t *)msg, MAX_RESP_REGS);

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

TEST_SERVICE(ffa_direct_message_req2_echo_services)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	struct ffa_partition_info target_info;
	struct ffa_uuid target_uuid;

	/* Retrieve uuid of target endpoint. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	HFTEST_LOG("Target UUID: %X-%X-%X-%X", target_uuid.uuid[0],
		   target_uuid.uuid[1], target_uuid.uuid[2],
		   target_uuid.uuid[3]);

	/* From uuid to respective partition info. */
	ASSERT_EQ(get_ffa_partition_info(target_uuid, &target_info,
					 sizeof(target_info), recv_buf),
		  1);

	HFTEST_LOG("Echo test with: %x", target_info.vm_id);

	res = ffa_msg_send_direct_req2(hf_vm_get_id(), target_info.vm_id,
				       &target_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);

	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
	EXPECT_EQ(res.extended_val.arg8, msg[4]);
	EXPECT_EQ(res.extended_val.arg9, msg[5]);
	EXPECT_EQ(res.extended_val.arg10, msg[6]);
	EXPECT_EQ(res.extended_val.arg11, msg[7]);
	EXPECT_EQ(res.extended_val.arg12, msg[8]);
	EXPECT_EQ(res.extended_val.arg13, msg[9]);
	EXPECT_EQ(res.extended_val.arg14, msg[10]);
	EXPECT_EQ(res.extended_val.arg15, msg[11]);
	EXPECT_EQ(res.extended_val.arg16, msg[12]);
	EXPECT_EQ(res.extended_val.arg17, msg[13]);

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

TEST_SERVICE(ffa_direct_message_v_1_2_cycle_denied)
{
	struct ffa_value res;
	struct ffa_value args;
	ffa_id_t sender;
	ffa_id_t receiver;
	ffa_id_t own_id = hf_vm_get_id();
	const uint64_t invalid_msg[] = {1, 2, 3, 4, 5};
	uint64_t msg[MAX_RESP_REGS];

	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_uuid target_uuid;

	/* Retrieve uuid of target endpoint. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	/* Wait for direct request. */
	args = ffa_msg_wait();

	ASSERT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);
	receiver = ffa_receiver(args);
	sender = ffa_sender(args);

	EXPECT_EQ(receiver, hf_vm_get_id());

	/* Try to send a request back instead of a response. */
	res = ffa_msg_send_direct_req2(own_id, sender, &target_uuid,
				       (const uint64_t *)&invalid_msg,
				       ARRAY_SIZE(invalid_msg));

	EXPECT_FFA_ERROR(res, FFA_DENIED);

	/* Send the echo through direct message response. */
	memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &args.arg4,
		 MAX_RESP_REGS * sizeof(uint64_t));

	ffa_msg_send_direct_resp2(receiver, sender, (const uint64_t *)msg,
				  MAX_RESP_REGS);

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_message_cycle_req_req2_denied)
{
	struct ffa_value res;
	struct ffa_value args;
	ffa_id_t sender;
	ffa_id_t receiver;
	ffa_id_t own_id = hf_vm_get_id();
	const uint64_t invalid_msg[] = {1, 2, 3, 4, 5};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_uuid target_uuid;

	/* Retrieve uuid of target endpoint. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	/* Wait for direct request. */
	args = ffa_msg_wait();
	ASSERT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);
	receiver = ffa_receiver(args);
	sender = ffa_sender(args);

	EXPECT_EQ(receiver, hf_vm_get_id());

	/* Try to send a request back instead of a response. */
	res = ffa_msg_send_direct_req2(own_id, sender, &target_uuid,
				       (const uint64_t *)&invalid_msg,
				       ARRAY_SIZE(invalid_msg));
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_yield_direct_message_v_1_2_echo_services)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	struct ffa_uuid target_uuid;
	struct ffa_partition_info target_info;

	/* Retrieve FF-A ID of the target endpoint. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	/* From uuid to respective partition info. */
	ASSERT_EQ(get_ffa_partition_info(target_uuid, &target_info,
					 sizeof(target_info), recv_buf),
		  1);

	HFTEST_LOG("Echo test with: %x", target_info.vm_id);

	res = ffa_msg_send_direct_req2(hf_vm_get_id(), target_info.vm_id,
				       &target_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	/*
	 * Be prepared to allocate CPU cycles to target vCPU if it yields while
	 * processing direct message.
	 */
	while (res.func == FFA_YIELD_32) {
		/* VM id/vCPU index are passed through arg1. */
		EXPECT_EQ(res.arg1, ffa_vm_vcpu(target_info.vm_id, 0));

		/* Allocate CPU cycles to resume SP. */
		res = ffa_run(target_info.vm_id, 0);
	}
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);

	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
	EXPECT_EQ(res.extended_val.arg8, msg[4]);
	EXPECT_EQ(res.extended_val.arg9, msg[5]);
	EXPECT_EQ(res.extended_val.arg10, msg[6]);
	EXPECT_EQ(res.extended_val.arg11, msg[7]);
	EXPECT_EQ(res.extended_val.arg12, msg[8]);
	EXPECT_EQ(res.extended_val.arg13, msg[9]);
	EXPECT_EQ(res.extended_val.arg14, msg[10]);
	EXPECT_EQ(res.extended_val.arg15, msg[11]);
	EXPECT_EQ(res.extended_val.arg16, msg[12]);
	EXPECT_EQ(res.extended_val.arg17, msg[13]);

	ffa_yield();
}

/**
 * Verify a service can't send a direct message response when it hasn't
 * first been sent a request.
 */
TEST_SERVICE(ffa_disallowed_direct_msg_resp2)
{
	struct ffa_value args;
	struct ffa_value ret;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service1_info = service1(recv_buf);
	uint64_t msg[MAX_RESP_REGS];

	ret = ffa_msg_send_direct_resp2(service1_info->vm_id, HF_PRIMARY_VM_ID,
					(uint64_t *)msg, ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	ffa_msg_send_direct_resp2(ffa_receiver(args), ffa_sender(args),
				  (uint64_t *)msg, ARRAY_SIZE(msg));

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_msg_req2_disallowed_smc)
{
	struct ffa_value args = ffa_msg_wait();
	struct ffa_value ret;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service1_info = service1(recv_buf);
	uint64_t msg[MAX_RESP_REGS] = {0};
	struct ffa_uuid sender_uuid;
	ffa_uuid_init(0, 0, 0, 0, &sender_uuid);

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	ret = ffa_msg_wait();
	EXPECT_FFA_ERROR(ret, FFA_DENIED);

	ret = ffa_msg_send_direct_req2(service1_info->vm_id, ffa_sender(args),
				       &sender_uuid, (uint64_t *)msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp2(ffa_receiver(args), ffa_sender(args),
				  (uint64_t *)msg, ARRAY_SIZE(msg));

	FAIL("Direct response not expected to return");
}

/**
 * Verify that services can't send direct message requests
 * via FFA_MSG_SEND_DIRECT_REQ2 after being invoked by FFA_RUN.
 */
TEST_SERVICE(ffa_disallowed_direct_msg_req2)
{
	struct ffa_value args;
	struct ffa_value ret;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service1_info;
	uint64_t msg[MAX_RESP_REGS] = {0};
	struct ffa_uuid target_uuid;

	/* Retrieve uuid of NWd PVM. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	service1_info = service1(recv_buf);

	/* Attempt request to NWd VM. */
	ret = ffa_msg_send_direct_req2(service1_info->vm_id, HF_PRIMARY_VM_ID,
				       &target_uuid, (uint64_t *)msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	ret = ffa_msg_send_direct_req2(service1_info->vm_id, HF_VM_ID_BASE + 10,
				       &target_uuid, (uint64_t *)msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	ffa_msg_send_direct_resp2(ffa_receiver(args), ffa_sender(args),
				  (uint64_t *)msg, ARRAY_SIZE(msg));

	FAIL("Direct response not expected to return");
}

/**
 * Verify a service can't send a response to a different VM than the one
 * that sent the request.
 * Verify a service cannot send a response with a sender ID different from
 * its own service ID.
 */
TEST_SERVICE(ffa_direct_msg_resp2_invalid_sender_receiver)
{
	struct ffa_value res;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	ffa_id_t invalid_receiver;
	uint64_t msg[MAX_RESP_REGS] = {0};
	ffa_id_t own_id;
	ffa_id_t sender;
	struct ffa_value args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	sender = ffa_sender(args);
	own_id = hf_vm_get_id();
	ASSERT_EQ(own_id, ffa_receiver(args));

	/* Other receiver ID. */
	invalid_receiver = ffa_is_vm_id(own_id) ? service2_info->vm_id : own_id;
	res = ffa_msg_send_direct_resp2(own_id, invalid_receiver,
					(uint64_t *)msg, ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	/* Spoof sender ID. */
	res = ffa_msg_send_direct_resp2(service2_info->vm_id, sender,
					(uint64_t *)msg, ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp2(own_id, sender, (uint64_t *)msg,
				  ARRAY_SIZE(msg));

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_msg_req2_resp_failure)
{
	struct ffa_value res;
	struct ffa_value args = ffa_msg_wait();
	uint64_t msg[MAX_RESP_REGS] = {0};

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);

	/* Respond to FFA_MSG_SEND_DIRECT_REQ2 with FFA_MSG_SEND_DIRECT_RESP. */
	res = ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				       args.arg3, args.arg4, args.arg5,
				       args.arg6, args.arg7);

	EXPECT_FFA_ERROR(res, FFA_DENIED);

	memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &args.arg4,
		 MAX_RESP_REGS * sizeof(uint64_t));
	ffa_msg_send_direct_resp2(ffa_receiver(args), ffa_sender(args),
				  (uint64_t *)msg, ARRAY_SIZE(msg));

	FAIL("Direct response not expected to return");
}

TEST_SERVICE(ffa_direct_msg_req_resp2_failure)
{
	struct ffa_value res;
	struct ffa_value args = ffa_msg_wait();
	uint64_t msg[MAX_RESP_REGS] = {0};

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &args.arg4,
		 MAX_RESP_REGS * sizeof(uint64_t));
	/* Respond to FFA_MSG_SEND_DIRECT_REQ with FFA_MSG_SEND_DIRECT_RESP2. */
	res = ffa_msg_send_direct_resp2(ffa_receiver(args), ffa_sender(args),
					(uint64_t *)msg, ARRAY_SIZE(msg));

	EXPECT_FFA_ERROR(res, FFA_DENIED);

	ffa_msg_send_direct_resp(ffa_receiver(args), ffa_sender(args),
				 args.arg3, args.arg4, args.arg5, args.arg6,
				 args.arg7);

	FAIL("Direct response not expected to return");
}

/**
 * Put SP in waiting state via FFA_MSG_SEND_DIRECT_RESP.
 * Make sure extended registers are preserved when SP is brought
 * into running state with receipt of FFA_MSG_SEND_DIRECT_REQ2.
 *
 * Run twice to cover the reverse scenario (SP waits with
 * FFA_MSG_SEND_DIRECT_RESP2 and wakes up with receipt of
 * FFA_MSG_SEND_DIRECT_REQ).
 */
TEST_SERVICE(ffa_direct_msg_resp_ext_registers_preserved)
{
	struct ffa_value args = ffa_msg_wait();
	uint64_t msg[MAX_RESP_REGS];

	for (uint32_t i = 0; i < 2; i++) {
		EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

		args = ffa_msg_send_direct_resp(
			ffa_receiver(args), ffa_sender(args), args.arg3,
			args.arg4, args.arg5, args.arg6, args.arg7);

		/*
		 * Wake up from waiting state with receipt of
		 * FFA_MSG_SEND_DIRECT_REQ2.
		 */
		EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ2_64);
		memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &args.arg4,
			 MAX_RESP_REGS * sizeof(uint64_t));

		args = ffa_msg_send_direct_resp2(
			ffa_receiver(args), ffa_sender(args),
			(const uint64_t *)msg, MAX_RESP_REGS);
	}

	FAIL("Direct response not expected to return");
}

/**
 * FF-A v1.1 endpoint attempts to use FFA_MSG_SEND_DIRECT_REQ2
 * and fails.
 */
TEST_SERVICE(version_does_not_support_req2)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	struct ffa_partition_info target_info;
	struct ffa_uuid target_uuid;

	/* Retrieve uuid of target endpoint. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	HFTEST_LOG("Target UUID: %X-%X-%X-%X", target_uuid.uuid[0],
		   target_uuid.uuid[1], target_uuid.uuid[2],
		   target_uuid.uuid[3]);

	/* From uuid to respective partition info. */
	ASSERT_EQ(get_ffa_partition_info(target_uuid, &target_info,
					 sizeof(target_info), recv_buf),
		  1);

	/* Attempt to send FFA_MSG_SEND_DIRECT_REQ2 and fail. */
	res = ffa_msg_send_direct_req2(hf_vm_get_id(), target_info.vm_id,
				       &target_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_DENIED);
	ffa_yield();
}

/**
 * Service traps execution in a loop, and expects to always wake up with a
 * FFA_MSG_SEND_DIRECT_REQ2. Verify that target UUID was specified in the target
 * partition's manifest before echoing message back to sender.
 */
TEST_SERVICE(ffa_direct_message_req2_resp_loop)
{
	struct hftest_context *ctx = hftest_get_context();
	struct ffa_uuid *uuids = get_uuids(ctx);
	uint16_t uuid_count = get_uuid_count(ctx);
	struct ffa_value res;

	if (!ctx->is_ffa_manifest_parsed) {
		FAIL("Manifest not parsed");
	}

	res = ffa_msg_wait();

	while (true) {
		uint64_t msg[MAX_RESP_REGS];
		struct ffa_uuid target_uuid;

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ2_64);

		ffa_uuid_from_u64x2(res.arg2, res.arg3, &target_uuid);

		HFTEST_LOG("Target UUID: %X-%X-%X-%X", target_uuid.uuid[0],
			   target_uuid.uuid[1], target_uuid.uuid[2],
			   target_uuid.uuid[3]);

		EXPECT_TRUE(is_uuid_in_list(uuid_count, target_uuid, uuids));

		memcpy_s(&msg, sizeof(uint64_t) * MAX_RESP_REGS, &res.arg4,
			 MAX_RESP_REGS * sizeof(uint64_t));

		res = ffa_msg_send_direct_resp2(
			ffa_receiver(res), ffa_sender(res),
			(const uint64_t *)msg, MAX_RESP_REGS);
	}
}

/**
 * Identifies the VM availiability message.
 * See section 18.3 of v1.2 FF-A specification.
 */
enum ffa_vm_availability_message {
	VM_MSG_CREATED,
	VM_MSG_DESTROYED,
};

/**
 * The state of a VM.
 * See section 18.3.2.3 of v1.2 FF-A specification.
 */
enum ffa_vm_availability_state {
	VM_STATE_UNAVAILABLE,
	VM_STATE_AVAILABLE,
	VM_STATE_ERROR,
};

/**
 * In the scope of the VM availability messages, the test SP is maintaining the
 * state of 4 VMs.
 */
static enum ffa_vm_availability_state vm_states[4] = {0};

static enum ffa_vm_availability_state next_vm_availability_state(
	enum ffa_vm_availability_state current_state,
	enum ffa_vm_availability_message msg)
{
	/* clang-format off */
	static const enum ffa_vm_availability_state table[3][2] = {
		/* State                VM created          VM destoyed          */
		/* VM unavailable  */ { VM_STATE_AVAILABLE, VM_STATE_ERROR       },
		/* VM available    */ { VM_STATE_ERROR,     VM_STATE_UNAVAILABLE },
		/* Error           */ { VM_STATE_ERROR,     VM_STATE_ERROR       },
	};
	/* clang-format on */

	return table[current_state][msg];
}

/**
 * Receive VM availability messages and update VM's state accordingly.
 */
TEST_SERVICE(vm_availability_messaging)
{
	struct ffa_value args = ffa_msg_wait();

	for (;;) {
		enum ffa_framework_msg_func func = ffa_framework_msg_func(args);
		ffa_id_t sender_id = ffa_sender(args);
		ffa_id_t receiver_id = ffa_receiver(args);
		ffa_id_t vm_id = ffa_vm_availability_message_vm_id(args);
		enum ffa_vm_availability_state current_state;
		enum ffa_vm_availability_state new_state;
		enum ffa_vm_availability_message msg;

		switch (func) {
		case FFA_FRAMEWORK_MSG_VM_CREATION_REQ:
			msg = VM_MSG_CREATED;
			break;
		case FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ:
			msg = VM_MSG_DESTROYED;
			break;
		default:
			dlog_verbose("Unknown framework message func: %#x\n",
				     func);
			return;
		}

		current_state = vm_states[vm_id];
		new_state = next_vm_availability_state(current_state, msg);
		vm_states[vm_id] = new_state;

		args = ffa_framework_message_send_direct_resp(
			receiver_id, sender_id,
			((msg == VM_MSG_CREATED)
				 ? FFA_FRAMEWORK_MSG_VM_CREATION_RESP
				 : FFA_FRAMEWORK_MSG_VM_DESTRUCTION_RESP),
			(new_state != VM_STATE_ERROR) ? 0
						      : FFA_INVALID_PARAMETERS);
	}
}

/**
 * Forward a framework message from primary VM, to demonstrate that SP cannot
 * send framework messages.
 */
TEST_SERVICE(vm_availability_messaging_send_from_sp)
{
	struct ffa_value args = ffa_msg_wait();

	for (;;) {
		enum ffa_framework_msg_func func = ffa_framework_msg_func(args);
		ffa_id_t sp_id = ffa_receiver(args);
		ffa_id_t pvm_id = ffa_sender(args);
		ffa_id_t vm_id = ffa_vm_availability_message_vm_id(args);

		struct ffa_value ret = ffa_framework_msg_send_direct_req(
			sp_id, pvm_id, func, vm_id);

		/* Verify that the framework message request failed. */
		ASSERT_EQ(ret.func, FFA_ERROR_32);
		ASSERT_EQ(ret.arg3, 0);

		/*
		 * Send a valid response, so that the PVM is not blocked
		 * forever.
		 */
		args = ffa_msg_send_direct_resp(sp_id, pvm_id, ret.func,
						ret.arg1, ret.arg2, ret.arg3,
						ret.arg4);
	}
}

/**
 * Forward a framework message from primary VM, to demonstrate that SP cannot
 * send non-framework messages in response to framework messages.
 */
TEST_SERVICE(vm_availability_messaging_send_non_framework_from_sp)
{
	struct ffa_value args = ffa_msg_wait();
	struct ffa_value ret;
	uint32_t ffa_func = args.func;
	ffa_id_t sp_id = ffa_receiver(args);
	ffa_id_t pvm_id = ffa_sender(args);

	ret = ffa_msg_send_direct_resp(sp_id, pvm_id, args.arg3, args.arg4,
				       args.arg5, args.arg6, args.arg7);

	/* Verify that the direct message response failed. */
	ASSERT_EQ(ret.func, FFA_ERROR_32);
	ASSERT_EQ((enum ffa_error)ret.arg2, FFA_DENIED);

	/* Send a valid response, so that the VM is not blocked forever. */
	args = ffa_framework_message_send_direct_resp(sp_id, pvm_id, ffa_func,
						      0);
	ASSERT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(ffa_sender(args), pvm_id);
	EXPECT_EQ(ffa_receiver(args), sp_id);
	EXPECT_EQ(args.arg2,
		  FFA_FRAMEWORK_MSG_BIT | FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ);
	ASSERT_EQ(args.arg3, 0);
}
