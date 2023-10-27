/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "sp_helpers.h"
#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static struct ffa_value handle_direct_req_cmd(struct ffa_value res)
{
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
	case SP_NOTIF_SET_CMD:
		res = sp_notif_set_cmd(ffa_sender(res), sp_notif_receiver(res),
				       sp_notif_flags(res),
				       sp_notif_bitmap(res));
		break;
	case SP_NOTIF_GET_CMD:
		res = sp_notif_get_cmd(ffa_sender(res), sp_notif_vcpu(res),
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
	case SP_CHECK_CPU_IDX_CMD:
		res = sp_check_cpu_idx_cmd(ffa_sender(res),
					   sp_check_cpu_idx(res));
		break;
	case SP_WAIT_BUSY_LOOP_CMD:
		sp_wait_loop(res.arg4);
		res = sp_success(ffa_receiver(res), ffa_sender(res), 0);
		break;
	case SP_CHECK_STATE_TRANSITIONS_CMD:
		res = sp_check_state_transitions_cmd(ffa_sender(res), res.arg4);
		break;
	case SP_VIRTUAL_INTERRUPT_CMD:
		res = sp_virtual_interrupt_cmd(ffa_sender(res),
					       sp_interrupt_id(res),
					       sp_is_interrupt_enable(res),
					       sp_interrupt_pin_type(res));
		break;
	case SP_TWDOG_START_CMD:
		res = sp_twdog_cmd(ffa_sender(res), res.arg4);
		break;
	case SP_TWDOG_MAP_CMD:
		res = sp_twdog_map_cmd(ffa_sender(res));
		break;
	case SP_LAST_INTERRUPT_SERVICED_CMD:
		res = sp_get_last_interrupt_cmd(ffa_sender(res));
		break;
	case SP_CLEAR_LAST_INTERRUPT_CMD:
		res = sp_clear_last_interrupt_cmd(ffa_sender(res));
		break;
	case SP_SLEEP_CMD:
		res = sp_sleep_cmd(ffa_sender(res), sp_get_sleep_time(res));
		break;
	case SP_FWD_SLEEP_CMD:
		res = sp_fwd_sleep_cmd(ffa_sender(res), sp_get_sleep_time(res),
				       sp_get_fwd_sleep_dest(res),
				       sp_get_fwd_sleep_interrupted_hint(res));
		break;
	case SP_CHECK_PARTITION_INFO_GET_REGS_CMD:
		res = sp_check_partition_info_get_regs_cmd(ffa_sender(res));
		break;
	case SP_YIELD_SEC_INTERRUPT_HANDLING_CMD:
		res = sp_yield_secure_interrupt_handling_cmd(ffa_sender(res),
							     res.arg4);
		break;
	case SP_ROUTE_SEC_INT_TARGET_VCPU_CMD:
		res = sp_route_interrupt_to_target_vcpu_cmd(
			ffa_sender(res), (ffa_vcpu_index_t)res.arg4,
			(uint32_t)res.arg5);
		break;
	case SP_TRIGGER_ESPI_CMD:
		res = sp_trigger_espi_cmd(ffa_sender(res), (uint32_t)res.arg4);
		break;
	default:
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "0x%x is not a valid command from %x\n",
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
	struct mailbox_buffers mb;
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
			res = handle_direct_req_cmd(res);
		} else if (res.func == FFA_INTERRUPT_32) {
			res = handle_ffa_interrupt(res);
		} else if (res.func == FFA_RUN_32) {
			res = handle_ffa_run(res);
		} else {
			HFTEST_LOG_FAILURE();
			HFTEST_LOG(HFTEST_LOG_INDENT
				   "0x%x is not a valid function\n",
				   res.func);
			abort();
		}
	}
}
