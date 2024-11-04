/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/fdt_handler.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "sp_helpers.h"
#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static struct ffa_value handle_direct_req2_cmd(struct ffa_value res)
{
	uint32_t options = res.arg6;

	hftest_set_dir_req_source_id(ffa_sender(res));

	if (res.arg4 == SP_SLEEP_CMD) {
		res = sp_sleep_cmd(ffa_sender(res), res.arg5, options,
				   FFA_MSG_SEND_DIRECT_REQ2_64);
	} else {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "0x%lx is not a valid command from %x\n",
			   res.arg4, ffa_sender(res));
		abort();
	}

	/* Reset the field tracking the source of direct request message. */
	hftest_set_dir_req_source_id(HF_INVALID_VM_ID);

	return res;
}

static struct ffa_value handle_direct_req_cmd(struct ffa_value res)
{
	hftest_set_dir_req_source_id(ffa_sender(res));

	enum sp_cmd cmd = res.arg3;
	switch (cmd) {
	case SP_ECHO_CMD:
		res = sp_echo_cmd(ffa_sender(res), res.arg3, res.arg4, res.arg5,
				  res.arg6, res.arg7);
		break;
	case SP_REQ_ECHO_CMD:
		res = sp_req_echo_cmd(ffa_sender(res), res.arg4, res.arg5,
				      res.arg6, res.arg7);
		break;
	case SP_REQ_ECHO_BUSY_CMD:
		res = sp_req_echo_busy_cmd(ffa_sender(res));
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
	case SP_LAST_INTERRUPT_SERVICED_CMD:
		res = sp_get_last_interrupt_cmd(ffa_sender(res));
		break;
	case SP_CLEAR_LAST_INTERRUPT_CMD:
		res = sp_clear_last_interrupt_cmd(ffa_sender(res));
		break;
	case SP_SLEEP_CMD:
		res = sp_sleep_cmd(ffa_sender(res), sp_get_sleep_time(res),
				   sp_get_sleep_options(res),
				   FFA_MSG_SEND_DIRECT_REQ_32);
		break;
	case SP_FWD_SLEEP_CMD:
		res = sp_fwd_sleep_cmd(ffa_sender(res), sp_get_sleep_time(res),
				       sp_get_fwd_sleep_dest(res),
				       sp_get_fwd_sleep_options(res));
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
	case SP_FFA_FEATURES_CMD:
		res = sp_ffa_features_cmd(ffa_sender(res), res.arg4);
		break;
	case SP_FFA_MEM_RETRIEVE_CMD:
		res = sp_ffa_mem_retrieve_cmd(ffa_sender(res), res.arg4,
					      res.arg5);
		break;
	case SP_GENERIC_TIMER_START_CMD:
		res = sp_generic_timer_cmd(ffa_sender(res), res.arg4);
		break;
	case SP_PAUTH_FAULT_CMD:
		sp_pauth_fault_cmd();
		break;
	case SP_PREPARE_SPMC_CALL_CHAIN_CMD:
		res = sp_prepare_spmc_call_chain_cmd(ffa_sender(res), res.arg4);
		break;
	case SP_PREPARE_PREEMPT_INT_HANDLING:
		res = sp_prepare_preempt_interrupt_handling_cmd(ffa_sender(res),
								res.arg4);
		break;
	case SP_ARCH_TIMER_CMD:
		res = sp_program_arch_timer_sleep_cmd(
			ffa_sender(res), sp_get_arch_timer_delay(res),
			sp_get_arch_timer_sleep(res),
			sp_get_arch_timer_fwd_call(res));
		break;
	default:
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "%#lx is not a valid command from %x\n",
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
	/* Use FF-A v1.1 EAC0 boot protocol to retrieve the FDT. */
	static struct ffa_boot_info_desc* fdt_info;
	struct mailbox_buffers mb;
	struct hftest_context* ctx = hftest_get_context();
	struct ffa_value res;

	if (is_boot_vcpu) {
		struct fdt fdt;
		void* fdt_ptr;
		struct ffa_boot_info_header* boot_info_header;
		extern void secondary_ep_entry(void);

		mb = set_up_mailbox();
		hftest_context_init(ctx, mb.send, mb.recv);
		boot_info_header = get_boot_info_header();

		fdt_info = get_boot_info_desc(boot_info_header,
					      FFA_BOOT_INFO_TYPE_STD,
					      FFA_BOOT_INFO_TYPE_ID_FDT);

		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		fdt_ptr = (void*)fdt_info->content;

		if (!fdt_struct_from_ptr(fdt_ptr, &fdt)) {
			HFTEST_LOG(HFTEST_LOG_INDENT
				   "Unable to access the FDT");
			abort();
		}

		hftest_parse_ffa_manifest(ctx, &fdt);

		/*
		 * Map MMIO address space of peripherals (such as secure
		 * watchdog timer) described as device region nodes in partition
		 * manifest.
		 */
		hftest_map_device_regions(ctx);
		sp_register_secondary_ep(ctx);
	} else {
		/*
		 * Primary core should have initialized the fdt_info structure.
		 */
		assert(fdt_info != NULL);
	}

	res = ffa_msg_wait();

	while (1) {
		if (res.func == FFA_MSG_SEND_DIRECT_REQ_32) {
			dlog_verbose("Received direct message request");
			res = handle_direct_req_cmd(res);
		} else if (res.func == FFA_MSG_SEND_DIRECT_REQ2_64) {
			dlog_verbose("Received direct message request2");
			res = handle_direct_req2_cmd(res);
		} else if (res.func == FFA_INTERRUPT_32) {
			dlog_verbose("Received FF-A interrupt.");
			res = handle_interrupt(res);
		} else if (res.func == FFA_RUN_32) {
			/*
			 * Received FFA_RUN in waiting state, the endpoint
			 * simply returns by FFA_MSG_WAIT.
			 */
			dlog_verbose("Received FFA_RUN...");
			ASSERT_EQ(res.arg1, 0);
			res = ffa_msg_wait();
		} else {
			HFTEST_LOG_FAILURE();
			HFTEST_LOG(HFTEST_LOG_INDENT
				   "0x%lx is not a valid function\n",
				   res.func);
			abort();
		}
	}
}
