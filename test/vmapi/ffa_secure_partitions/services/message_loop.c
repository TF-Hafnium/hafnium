/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/abort.h"
#include "test/hftest.h"

/**
 * Message loop to add tests to be controlled by the control partition(depends
 * on the test set-up).
 */
noreturn void test_main_sp(bool is_boot_vcpu)
{
	struct ffa_value res = ffa_msg_wait();

	while (1) {
		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);

		if (is_boot_vcpu) {
			/* TODO: can only print from boot vCPU. */
			HFTEST_LOG("Received direct message request");
		}

		switch (res.arg3) {
		case SP_ECHO_CMD:
			res = sp_echo_cmd(ffa_sender(res), res.arg3, res.arg4,
					  res.arg5, res.arg6, res.arg7);
			break;
		case SP_REQ_ECHO_CMD:
			res = sp_req_echo_cmd(ffa_sender(res), res.arg4,
					      res.arg5, res.arg6, res.arg7);
			break;
		case SP_REQ_ECHO_BUSY_CMD:
			res = sp_req_echo_busy_cmd(ffa_sender(res));
			break;
		case SP_NOTIF_SET_CMD:
			res = sp_notif_set_cmd(
				ffa_sender(res), sp_notif_receiver(res),
				sp_notif_flags(res), sp_notif_bitmap(res));
			break;
		case SP_NOTIF_GET_CMD:
			res = sp_notif_get_cmd(ffa_sender(res),
					       sp_notif_vcpu(res),
					       sp_notif_flags(res));
			break;
		case SP_NOTIF_BIND_CMD:
			res = sp_notif_bind_cmd(
				ffa_sender(res), sp_notif_bind_sender(res),
				sp_notif_flags(res), sp_notif_bitmap(res));
			break;
		case SP_NOTIF_UNBIND_CMD:
			res = sp_notif_unbind_cmd(ffa_sender(res),
						  sp_notif_bind_sender(res),
						  sp_notif_bitmap(res));
			break;
		default:
			HFTEST_LOG_FAILURE();
			HFTEST_LOG(HFTEST_LOG_INDENT
				   "0x%x is not a valid command id\n",
				   res.arg3);
			abort();
		}
	}
}
