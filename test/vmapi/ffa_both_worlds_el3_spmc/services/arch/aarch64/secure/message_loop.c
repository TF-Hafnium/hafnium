/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/check.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

struct mailbox_buffers mb;

static struct ffa_value handle_direct_req_cmd(struct mailbox_buffers mb,
					      struct ffa_value res)
{
	CHECK(mb.recv != NULL);
	CHECK(mb.send != NULL);

	hftest_set_dir_req_source_id(ffa_sender(res));

	switch (res.arg3) {
	case SP_ECHO_CMD:
		res = sp_echo_cmd(ffa_sender(res), res.arg3, res.arg4, res.arg5,
				  res.arg6, res.arg7);
		break;
	case SP_REQ_ECHO_CMD:
		res = sp_req_echo_cmd(ffa_sender(res), res.arg4, res.arg5,
				      res.arg6, res.arg7);
		break;
	case SP_REQ_ECHO_DENIED_CMD:
		res = sp_req_echo_denied_cmd(ffa_sender(res));
		break;
	case SP_CHECK_PARTITION_INFO_GET_REGS_CMD:
		res = sp_check_partition_info_get_regs_cmd(ffa_sender(res));
		break;
	case SP_REQ_RETRIEVE_CMD:
		res = sp_req_retrieve_cmd(ffa_sender(res), res.arg4, res.arg5,
					  res.arg6, mb);
		break;
	default:
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "0x%lx is not a valid command from %x\n",
			   res.arg3, ffa_sender(res));
		abort();
	}

	/* Reset the field tracking the source of direct request message. */
	hftest_set_dir_req_source_id(HF_INVALID_VM_ID);

	return res;
}

/**
 * Message loop to add tests to be controlled by the control partition(depends
 * on the test set-up).
 */
noreturn void test_main_sp(bool is_boot_vcpu)
{
	struct hftest_context* ctx = hftest_get_context();
	struct ffa_value res;

	if (is_boot_vcpu) {
		mb = set_up_mailbox();
		hftest_context_init(ctx, mb.send, mb.recv);
	}

	res = ffa_msg_wait();

	while (1) {
		if (res.func == FFA_MSG_SEND_DIRECT_REQ_32) {
			if (is_boot_vcpu) {
				/* TODO: can only print from boot vCPU. */
				HFTEST_LOG("Received direct message request");
			}
			res = handle_direct_req_cmd(mb, res);
		} else {
			HFTEST_LOG_FAILURE();
			HFTEST_LOG(HFTEST_LOG_INDENT
				   "0x%lx is not a valid function\n",
				   res.func);
			abort();
		}
	}
}
