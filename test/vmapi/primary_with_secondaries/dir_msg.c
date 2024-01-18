/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define MAX_RESP_REGS (MAX_MSG_SIZE / sizeof(uint64_t))

/**
 * Send direct message, verify that sent info is echoed back.
 */
TEST(direct_message, ffa_send_direct_message_req_echo)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_direct_message_resp_echo",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, service1_info->vm_id,
				      msg[0], msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);
}

/**
 * Send direct message to an VM/SP. Expect it to yield its CPU cycles. Allocate
 * cycles through FFA_RUN and verify that sent info is echoed back.
 */
TEST(direct_message, ffa_send_direct_message_req_yield_echo)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_yield_direct_message_resp_echo", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, service1_info->vm_id,
				      msg[0], msg[1], msg[2], msg[3], msg[4]);

	/*
	 * Consider the scenario where VM1 allocated CPU cycles to SP1 through
	 * a direct request message but SP1 yields execution back to VM1
	 * instead of busy waiting for an IO operation.
	 */
	EXPECT_EQ(res.func, FFA_YIELD_32);

	/* SP1 id/vCPU index are passed through arg1. */
	EXPECT_EQ(res.arg1, ffa_vm_vcpu(service1_info->vm_id, 0));

	/*
	 * Additionally, SP1 can also specify timeout while yielding cycles
	 * back to VM1. This is a hint to VM1 that it can be resumed upon
	 * expiration of the timeout.
	 * Check for 64-bit timeout specified by SP1 through arg2 and arg3. The
	 * purpose of these checks is just to validate the timeout value but
	 * not to leverage it upon expiration.
	 */
	EXPECT_EQ(res.arg2, 0x1);
	EXPECT_EQ(res.arg3, 0x23456789);

	/* Allocate CPU cycles to resume SP. */
	res = ffa_run(service1_info->vm_id, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);
}

/**
 * Initiate direct message request between test SPs.
 * If test services are VMs, test should be skipped.
 */
TEST_PRECONDITION(direct_message, ffa_direct_message_services_echo,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;

	/* Run service2 for it to wait for a request from service1. */
	SERVICE_SELECT(service2_info->vm_id, "ffa_direct_message_resp_echo",
		       mb.send);
	ffa_run(service2_info->vm_id, 0);

	/* Service1 requests echo from service2. */
	SERVICE_SELECT(service1_info->vm_id, "ffa_direct_message_echo_services",
		       mb.send);

	/* Send to service1 the uuid of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_info->vm_id,
				    sizeof(service2_info->vm_id), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_run(service1_info->vm_id, 0);
}

/**
 * Initiate direct message request between two Secure Partitions. Configure
 * the second SP in the call chain to yield cycles received from first SP
 * through direct message request. The first SP is equipped to reallocate
 * CPU cycles to resume the direct message processing.
 */
TEST_PRECONDITION(direct_message, ffa_direct_message_services_yield_echo,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;

	/* Run service2 for it to wait for a request from service1. */
	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_yield_direct_message_resp_echo", mb.send);
	ffa_run(service2_info->vm_id, 0);

	/* Service1 requests echo from service2. */
	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_yield_direct_message_echo_services", mb.send);

	/* Send to service1 the FF-A ID of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_info->vm_id,
				    sizeof(service2_info->vm_id), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * If Hafnium is the hypervisor, and service1 is a VM:
 * - Service verifies disallowed SMC invocations while ffa_msg_send_direct_req
 * is being serviced.
 * If Hafnium as SPMC is deployed and service1 is an SP:
 * - Validate the state transitions permitted under RTM_FFA_DIR_REQ partition
 * runtime model
 */
TEST(direct_message, ffa_send_direct_message_req_disallowed_smc)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_msg_req_disallowed_smc", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req(hf_vm_get_id(), service1_info->vm_id,
				      msg[0], msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Send direct message to invalid destination.
 */
TEST(direct_message, ffa_send_direct_message_req_invalid_dst)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct ffa_value res;

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, HF_PRIMARY_VM_ID,
				      msg[0], msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Verify that the primary VM can't send direct message responses.
 */
TEST(direct_message, ffa_send_direct_message_resp_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_direct_message_resp_echo",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_resp(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Test has two purposes. It runs the test service via ffa_run, and validates
 * that:
 * - If service is an SP, it can't send a direct message request to a VM in the
 * NWd.
 * - If service is a secondary VM, it can't invoke a direct message request to
 * the PVM (legacy behavior, for hafnium as an hypervisor).
 */
TEST(direct_message, ffa_secondary_direct_msg_req_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_disallowed_direct_msg_req",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, service1_info->vm_id, 0,
				      0, 0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Run secondary VM without sending a direct message request beforehand.
 * Secondary VM must fail sending a direct message response.
 */
TEST(direct_message, ffa_secondary_direct_msg_resp_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_disallowed_direct_msg_resp",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, service1_info->vm_id, 0,
				      0, 0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Run secondary VM and send a direct message request. Secondary VM attempts
 * altering the sender and receiver in its direct message responses, and must
 * fail to do so.
 */
TEST(direct_message, ffa_secondary_spoofed_response)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_msg_resp_invalid_sender_receiver", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, service1_info->vm_id, 0,
				      0, 0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/*
 * Validate that the creation of a cyclic dependency via direct_messaging
 * is not possible.
 * The test only makes sense in the scope of validating the SPMC, as the
 * hypervisor limits the direct message requests to be only invoked from
 * the primary VM. Thus, using precondition that checks both involved test
 * services are SPs.
 */
TEST_PRECONDITION(direct_message, fail_if_cyclic_dependency,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;

	/* Run service2 for it to wait for a request from service1. */
	SERVICE_SELECT(service2_info->vm_id, "ffa_direct_message_cycle_denied",
		       mb.send);
	ffa_run(service2_info->vm_id, 0);

	/* Service1 requests echo from service2. */
	SERVICE_SELECT(service1_info->vm_id, "ffa_direct_message_echo_services",
		       mb.send);

	/* Send to service1 the uuid of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_info->vm_id,
				    sizeof(service2_info->vm_id), 0);

	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
}

/**
 * Send direct message via FFA_MSG_SEND_DIRECT_REQ2, verify that sent info is
 * echoed back.
 */
TEST(direct_message, ffa_send_direct_message_req2_echo)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_uuid uuid = SERVICE1;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_message_req2_resp_echo", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &uuid, (const uint64_t *)&msg,
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
}

/**
 * Send direct message to an VM/SP. Expect it to yield its CPU cycles. Allocate
 * cycles through FFA_RUN and verify that sent info is echoed back.
 */
TEST(direct_message, ffa_send_direct_message_req2_yield_echo)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_uuid uuid = SERVICE1;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_yield_direct_message_resp2_echo", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));

	/*
	 * Consider the scenario where VM1 allocated CPU cycles to service1
	 * through a direct request message but service1 yields execution back
	 * to VM1 instead of busy waiting for an IO operation.
	 */
	EXPECT_EQ(res.func, FFA_YIELD_32);

	/* Service1 id/vCPU index are passed through arg1. */
	EXPECT_EQ(res.arg1, ffa_vm_vcpu(service1_info->vm_id, 0));

	/*
	 * Additionally, service1 can also specify timeout while yielding cycles
	 * back to VM1. This is a hint to VM1 that it can be resumed upon
	 * expiration of the timeout.
	 * Check for 64-bit timeout specified by service1 through arg2 and arg3.
	 * The purpose of these checks is just to validate the timeout value but
	 * not to leverage it upon expiration.
	 */
	EXPECT_EQ(res.arg2, 0x1);
	EXPECT_EQ(res.arg3, 0x23456789);

	/* Allocate CPU cycles to resume service */
	res = ffa_run(service1_info->vm_id, 0);

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
}

/**
 * Initiate direct message request between test SPs.
 * If test services are VMs, test should be skipped.
 */
TEST_PRECONDITION(direct_message, ffa_direct_message_req2_services_echo,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;
	const struct ffa_uuid service2_uuid = SERVICE2;

	/* Run service2 for it to wait for a request from service1. */
	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_direct_message_req2_resp_echo", mb.send);
	ffa_run(service2_info->vm_id, 0);

	/* Service1 requests echo from service2. */
	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_message_req2_echo_services", mb.send);

	/* Send to service1 the uuid of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_uuid, sizeof(service2_uuid), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_run(service1_info->vm_id, 0);
}

/**
 * Initiate direct message request between two Secure Partitions. Configure
 * the second SP in the call chain to yield cycles received from first SP
 * through direct message request. The first SP is equipped to reallocate
 * CPU cycles to resume the direct message processing.
 */
TEST_PRECONDITION(direct_message, ffa_direct_message_req2_services_yield_echo,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;
	const struct ffa_uuid service2_uuid = SERVICE2;

	/* Run service2 for it to wait for a request from service1. */
	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_yield_direct_message_resp2_echo", mb.send);
	ffa_run(service2_info->vm_id, 0);

	/* Service1 requests echo from service2. */
	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_yield_direct_message_v_1_2_echo_services", mb.send);

	/* Send to service1 the UUID of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_uuid, sizeof(service2_uuid), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * If Hafnium is the hypervisor, and service1 is a VM:
 * - Service verifies disallowed SMC invocations while ffa_msg_send_direct_req
 * is being serviced.
 *
 * If Hafnium as SPMC is deployed and service1 is an SP:
 * - Validate the state transitions permitted under RTM_FFA_DIR_REQ partition
 * runtime model
 */
TEST(direct_message, ffa_send_direct_message_req2_disallowed_smc)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	const struct ffa_uuid service1_uuid = SERVICE1;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_msg_req2_disallowed_smc", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(hf_vm_get_id(), service1_info->vm_id,
				       &service1_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
}

/**
 * Send direct message via FFA_MSG_SEND_DIRECT_REQ2 targeting an invalid UUID.
 */
TEST(direct_message, ffa_send_direct_message_req2_invalid_uuid)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_uuid uuid;

	/* Non-existent UUID. */
	ffa_uuid_init(1, 1, 1, 1, &uuid);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);

	/* UUID for a different partition than given FF-A id. */
	uuid = SERVICE2;
	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Verify that the primary VM can't send direct message responses
 * via FFA_MSG_SEND_DIRECT_RESP2_64.
 */
TEST(direct_message, ffa_send_direct_message_resp2_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	const uint64_t msg[] = {1, 2, 3, 4, 5};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_message_req2_resp_echo", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_resp2(HF_PRIMARY_VM_ID, service1_info->vm_id,
					(const uint64_t *)&msg,
					ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Test runs the test service via ffa_run, and validates that:
 * - If service is an SP, it can't send a direct message request to a VM in the
 * NWd.
 *
 * Legacy case for secondary VM
 * - If service is a secondary VM, it can't invoke a direct message request to
 * the PVM (legacy behavior, for hafnium as an hypervisor).
 */
TEST(direct_message, ffa_secondary_direct_msg_req2_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	const struct ffa_uuid service1_uuid = SERVICE1;
	uint64_t msg[MAX_RESP_REGS] = {0};
	struct ffa_uuid own_uuid = PVM;

	SERVICE_SELECT(service1_info->vm_id, "ffa_disallowed_direct_msg_req2",
		       mb.send);
	res = send_indirect_message(HF_PRIMARY_VM_ID, service1_info->vm_id,
				    mb.send, &own_uuid, sizeof(own_uuid), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &service1_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
}

/**
 * Run secondary VM without sending a direct message request beforehand.
 * Secondary VM must fail sending a direct message response.
 */
TEST(direct_message, ffa_secondary_direct_msg_resp2_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_uuid service1_uuid = SERVICE1;
	uint64_t msg[MAX_RESP_REGS] = {0};

	SERVICE_SELECT(service1_info->vm_id, "ffa_disallowed_direct_msg_resp2",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &service1_uuid, (uint64_t *)msg,
				       ARRAY_SIZE(msg));

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
}

/**
 * Run secondary VM and send a direct message request. Secondary VM attempts
 * altering the sender and receiver in its direct message responses, and must
 * fail to do so.
 */
TEST(direct_message, ffa_secondary_spoofed_response2)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_uuid service1_uuid = SERVICE1;
	uint64_t msg[MAX_RESP_REGS] = {0};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_msg_resp2_invalid_sender_receiver", mb.send);
	ffa_run(service1_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &service1_uuid, (uint64_t *)msg,
				       ARRAY_SIZE(msg));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
}

/**
 * Validate that the creation of a cyclic dependency via direct messaging
 * interfaces introduced in FF-A v1.2 is not possible. The test only makes sense
 * in the scope of validating the SPMC, as the hypervisor limits the direct
 * message requests to be only invoked from the primary VM. Thus, using
 * precondition that checks both involved test services are SPs.
 */
TEST_PRECONDITION(direct_message, fail_if_cyclic_dependency_v1_2,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_uuid service1_uuid = SERVICE1;
	struct ffa_uuid service2_uuid = SERVICE2;
	struct ffa_value ret;

	/*
	 * Run service2 for it to wait for a request from service1 after
	 * receiving indirect message containing uuid.
	 */
	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_direct_message_v_1_2_cycle_denied", mb.send);

	/* Send to service2 the uuid of service1 for its attempted message. */
	ret = send_indirect_message(own_id, service2_info->vm_id, mb.send,
				    &service1_uuid, sizeof(service1_uuid), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_run(service2_info->vm_id, 0);

	/* Service1 requests echo from service2. */
	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_message_req2_echo_services", mb.send);

	/* Send to service1 the uuid of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_uuid, sizeof(service2_uuid), 0);

	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
}

/**
 * Send a direct message request via FFA_MSG_SEND_DIR_REQ2 to each of the target
 * partition's UUIDs and  verify that sent info is echoed back.
 */
TEST_PRECONDITION(direct_message, ffa_send_direct_message_req2_multiple_uuids,
		  service1_and_service2_are_secure)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_uuid uuid = SERVICE2_UUID2;

	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_direct_message_req2_resp_loop", mb.send);
	ffa_run(service2_info->vm_id, 0);

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service2_info->vm_id,
				       &uuid, (const uint64_t *)&msg,
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

	uuid = SERVICE2;

	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service2_info->vm_id,
				       &uuid, (const uint64_t *)&msg,
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
}

/**
 * Test that a request sent via:
 *  - FFA_MSG_SEND_DIRECT_REQ2 cannot be completed by FFA_MSG_SEND_DIRECT_RESP
 *  - FFA_MSG_SEND_DIRECT_REQ cannot be completed by FFA_MSG_SEND_DIRECT_RESP2
 */
TEST(direct_message, ffa_direct_msg_check_abi_pairs_nwd_to_sp)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_uuid uuid1 = SERVICE1;

	/* Setup Service1 to respond with FFA_MSG_SEND_DIRECT_RESP ABI. */
	SERVICE_SELECT(service1_info->vm_id, "ffa_direct_msg_req2_resp_failure",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	/* Send a direct request with FFA_MSG_SEND_DIRECT_REQ2. */
	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service1_info->vm_id,
				       &uuid1, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);

	/* Set up Service2 to respond with FFA_MSG_SEND_DIRECT_RESP2 ABI. */
	SERVICE_SELECT(service2_info->vm_id, "ffa_direct_msg_req_resp2_failure",
		       mb.send);
	ffa_run(service2_info->vm_id, 0);

	/*
	 * Send a direct request with FFA_MSG_SEND_DIRECT_REQ and expect
	 * failure.
	 */
	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, service2_info->vm_id,
				      msg[0], msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Ensure that an SP that enters the waiting state with FFA_MSG_SEND_DIRECT_RESP
 * can preserve extended registers when resumed by FFA_MSG_SEND_DIRECT_REQ2.
 *
 * Run twice to cover the reverse scenario - SP enters waiting state with
 * FFA_MSG_SEND_DIRECT_RESP2 and is resumed by FFA_MSG_SEND_DIRECT_REQ.
 */
TEST(direct_message, ffa_direct_message_req2_after_req)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_uuid uuid1 = SERVICE1;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_direct_msg_resp_ext_registers_preserved", mb.send);
	ffa_run(service1_info->vm_id, 0);

	for (uint32_t i = 0; i < 2; i++) {
		/* Send a direct request with FFA_MSG_SEND_DIRECT_REQ. */
		res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID,
					      service1_info->vm_id, msg[0],
					      msg[1], msg[2], msg[3], msg[4]);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

		EXPECT_EQ(res.arg3, msg[0]);
		EXPECT_EQ(res.arg4, msg[1]);
		EXPECT_EQ(res.arg5, msg[2]);
		EXPECT_EQ(res.arg6, msg[3]);
		EXPECT_EQ(res.arg7, msg[4]);
		EXPECT_EQ(res.extended_val.arg8, 0);
		EXPECT_EQ(res.extended_val.arg9, 0);
		EXPECT_EQ(res.extended_val.arg10, 0);
		EXPECT_EQ(res.extended_val.arg11, 0);
		EXPECT_EQ(res.extended_val.arg12, 0);
		EXPECT_EQ(res.extended_val.arg13, 0);
		EXPECT_EQ(res.extended_val.arg14, 0);
		EXPECT_EQ(res.extended_val.arg15, 0);
		EXPECT_EQ(res.extended_val.arg16, 0);
		EXPECT_EQ(res.extended_val.arg17, 0);

		/* Send a direct request with FFA_MSG_SEND_DIRECT_REQ2. */
		res = ffa_msg_send_direct_req2(
			HF_PRIMARY_VM_ID, service1_info->vm_id, &uuid1,
			(const uint64_t *)&msg, ARRAY_SIZE(msg));

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
	}
}

/**
 * Test showing that an FF-A v1.1 endpoint (service4) cannot send a direct
 * request via FFA_MSG_SEND_DIRECT_REQ2.
 */
TEST_PRECONDITION(direct_message,
		  ffa_msg_send_direct_req2_send_v1_1_not_supported,
		  service1_is_not_vm)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service4_info = service4(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;
	const struct ffa_uuid service1_uuid = SERVICE1;

	/*
	 * Service4 requests echo from service1.
	 * Request sent via FFA_MSG_SEND_DIRECT_REQ2 should fail as Service4
	 * FF-A version is < FF-A v1.2.
	 */
	SERVICE_SELECT(service4_info->vm_id, "version_does_not_support_req2",
		       mb.send);

	/* Send to service4 the uuid of the target for its message. */
	ret = send_indirect_message(own_id, service4_info->vm_id, mb.send,
				    &service1_uuid, sizeof(service1_uuid), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_run(service4_info->vm_id, 0);
}

/**
 * Test showing that an FF-A v1.1 endpoint (service3) cannot receive a direct
 * request via FFA_MSG_SEND_DIRECT_REQ2.
 *
 * Also show an FF-A v1.2 endpoint (service4) that does not specify receipt of
 * direct requsts via FFA_MSG_SEND_DIRECT_REQ2 in its manifest cannot receive a
 * direct request via this function id.
 */
TEST_PRECONDITION(direct_message, ffa_msg_send_direct_req2_recv_not_supported,
		  service1_and_service2_are_secure)
{
	const uint64_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999, 0x01010101, 0x23232323, 0x45454545,
				0x67676767, 0x89898989, 0x11001100, 0x22332233,
				0x44554455, 0x66776677};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service3_info = service3(mb.recv);
	struct ffa_partition_info *service4_info = service4(mb.recv);
	struct ffa_value res;
	const struct ffa_uuid service3_uuid = SERVICE3;
	const struct ffa_uuid service4_uuid = SERVICE4;

	/* Send a direct request with FFA_MSG_SEND_DIRECT_REQ2. */
	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service3_info->vm_id,
				       &service3_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	SERVICE_SELECT(service4_info->vm_id,
		       "ffa_direct_message_req2_resp_echo", mb.send);
	ffa_run(service4_info->vm_id, 0);

	/* Send a direct request with FFA_MSG_SEND_DIRECT_REQ2. */
	res = ffa_msg_send_direct_req2(HF_PRIMARY_VM_ID, service4_info->vm_id,
				       &service4_uuid, (const uint64_t *)&msg,
				       ARRAY_SIZE(msg));
	EXPECT_FFA_ERROR(res, FFA_DENIED);
}
