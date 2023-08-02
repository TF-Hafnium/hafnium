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
