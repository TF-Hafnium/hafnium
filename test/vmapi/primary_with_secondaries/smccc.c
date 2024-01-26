/*
 * Copyright 2024 The Hafnium Authors.
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
 * An FFA_MSG_SEND_DIRECT_REQ call is emitted at the Secure virtual
 * FF-A instance from a v1.2 FF-A endpoint targeting a v1.1 endpoint.
 *
 * The service does not require results in registers beyond x7, hence per
 * SMCCCv1.2 ensure GP registers beyond x7 are preserved by callee.
 */
TEST_PRECONDITION(arch, smccc_direct_message_services_echo_sender_v1_2,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info =
		service1(mb.recv); /* FF-A >= v1.2 sender */
	struct ffa_partition_info *service4_info =
		service4(mb.recv); /* FF-A <= v1.1 receiver */
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;

	/* Run service4 for it to wait for a request from service1. */
	SERVICE_SELECT(service4_info->vm_id,
		       "smccc_ffa_msg_wait_and_response_callee_preserved",
		       mb.send);
	ffa_run(service4_info->vm_id, 0);

	/* Service1 requests echo from service4. */
	SERVICE_SELECT(service1_info->vm_id,
		       "smccc_ffa_direct_request_callee_preserved", mb.send);

	/* Send to service1 the FF-A id of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service4_info->vm_id,
				    sizeof(service4_info->vm_id), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_run(service1_info->vm_id, 0);
}

/**
 * An FFA_MSG_SEND_DIRECT_REQ call is emitted at the Secure virtual
 * FF-A instance from a v1.1 FF-A endpoint targeting a v1.2 endpoint.
 *
 * The service does not require results in registers beyond x7, hence per
 * SMCCCv1.2 ensure GP registers beyond x7 are preserved by callee.
 */
TEST_PRECONDITION(arch, smccc_direct_message_services_echo_sender_v1_1,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info =
		service1(mb.recv); /* FF-A >= v1.2 receiver */
	struct ffa_partition_info *service4_info =
		service4(mb.recv); /* FF-A <= v1.1 sender */
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;

	/* Run service1 for it to wait for a request from service4. */
	SERVICE_SELECT(service1_info->vm_id,
		       "smccc_ffa_msg_wait_and_response_callee_preserved",
		       mb.send);
	ffa_run(service1_info->vm_id, 0);

	/* Service4 requests echo from service1. */
	SERVICE_SELECT(service4_info->vm_id,
		       "smccc_ffa_direct_request_callee_preserved", mb.send);

	/* Send to service4 the FF-A id of the target for its message. */
	ret = send_indirect_message(own_id, service4_info->vm_id, mb.send,
				    &service1_info->vm_id,
				    sizeof(service1_info->vm_id), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_run(service4_info->vm_id, 0);
}
