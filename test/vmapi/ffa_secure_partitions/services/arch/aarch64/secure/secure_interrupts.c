/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "ap_refclk_generic_timer.h"
#include "partition_services.h"
#include "sp_helpers.h"
#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

bool yield_while_handling_sec_interrupt = false;
bool initiate_spmc_call_chain = false;
bool preempt_interrupt_handling = false;

/*
 * This variable is set by the request that processes the arch timer commands
 * from the PVM.
 */
extern uint32_t periodic_timer_ms;

static void send_managed_exit_response(ffa_id_t dir_req_source_id)
{
	struct ffa_value ffa_ret;
	bool waiting_resume_after_managed_exit;
	ffa_id_t own_id = hf_vm_get_id();

	/* Send managed exit response. */
	ffa_ret = sp_send_response(own_id, dir_req_source_id,
				   HF_MANAGED_EXIT_INTID);
	waiting_resume_after_managed_exit = true;

	while (waiting_resume_after_managed_exit) {
		waiting_resume_after_managed_exit =
			(ffa_ret.func != FFA_MSG_SEND_DIRECT_REQ_32) ||
			ffa_sender(ffa_ret) != dir_req_source_id ||
			sp_get_cmd(ffa_ret) != SP_RESUME_AFTER_MANAGED_EXIT;

		if (waiting_resume_after_managed_exit) {
			HFTEST_LOG(
				"Expected a direct message request from "
				"endpoint %x with command "
				"SP_RESUME_AFTER_MANAGED_EXIT",
				dir_req_source_id);
			ffa_ret = sp_error(own_id, ffa_sender(ffa_ret), 0);
		}
	}
	HFTEST_LOG("Resuming the suspended command");
}

static void deactivate_interrupt_and_yield(uint32_t intid)
{
	/* Perform secure interrupt de-activation. */
	ASSERT_EQ(hf_interrupt_deactivate(intid), 0);

	if (yield_while_handling_sec_interrupt) {
		struct ffa_value ret;
		HFTEST_LOG("Yield cycles while handling secure interrupt");
		ret = ffa_yield();

		ASSERT_EQ(ret.func, FFA_SUCCESS_32);
		HFTEST_LOG("Resuming secure interrupt handling");
	}

	exception_handler_set_last_interrupt(intid);
}

static void irq_current(void)
{
	uint32_t intid;
	struct ffa_value ffa_ret;
	ffa_id_t dir_req_source_id = hftest_get_dir_req_source_id();
	ffa_id_t own_id = hf_vm_get_id();

	intid = hf_interrupt_get();

	switch (intid) {
	case HF_MANAGED_EXIT_INTID: {
		HFTEST_LOG("vIRQ: Sending ME response to %x",
			   dir_req_source_id);
		send_managed_exit_response(dir_req_source_id);
		break;
	}
	case IRQ_TWDOG_INTID: {
		/*
		 * Interrupt triggered due to Trusted watchdog timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		HFTEST_LOG("Trusted WatchDog timer stopped: %u", intid);
		twdog_stop();

		if (initiate_spmc_call_chain) {
			HFTEST_LOG(
				"Initiating call chain in SPMC scheduled mode");
			/*
			 * The current SP sends a direct request message to
			 * another SP to mimic a long SPMC scheduled call
			 * chain.
			 */
			ffa_ret = sp_sleep_cmd_send(
				own_id, sp_find_next_endpoint(own_id), 50, 0);
			ASSERT_EQ(ffa_ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
		} else if (preempt_interrupt_handling) {
			/*
			 * Trigger the timer interrupt to mimic a physical
			 * interrupt preempting the current virtual interrupt
			 * handling.
			 */
			program_ap_refclk_timer(1);

			/* Wait to make sure the generic timer interrupt
			 * triggers. */
			sp_sleep_active_wait(5);
		}

		deactivate_interrupt_and_yield(intid);
		break;
	}
	case IRQ_AP_REFCLK_BASE1_INTID: {
		/*
		 * Interrupt triggered due to AP_REFCLK Generic timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		HFTEST_LOG("AP_REFCLK timer stopped: %u", intid);
		cancel_ap_refclk_timer();

		deactivate_interrupt_and_yield(intid);
		break;
	}
	case HF_VIRTUAL_TIMER_INTID: {
		/* Disable the EL1 physical arch timer. */
		timer_disable();
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);

		exception_handler_set_last_interrupt(intid);

		/* Configure timer to expire periodically. */
		timer_set(periodic_timer_ms);
		timer_start();
		HFTEST_LOG("EL1 Physical timer stopped and restarted");
		break;
	}
	default:
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT "Unsupported interrupt id: %u\n",
			   intid);
		abort();
	}
}

struct ffa_value sp_virtual_interrupt_cmd(ffa_id_t test_source,
					  uint32_t interrupt_id, bool enable,
					  uint32_t pin)
{
	int64_t ret;
	ffa_id_t own_id = hf_vm_get_id();

	ret = hf_interrupt_enable(interrupt_id, enable, pin);
	if (ret != 0) {
		return sp_error(own_id, test_source, 0);
	}

	ASSERT_EQ(pin, INTERRUPT_TYPE_IRQ);

	/*
	 * Register interrupt handler for virtual interrupt signaled by
	 * SPMC through vIRQ.
	 */
	exception_setup(irq_current, NULL);
	sp_enable_irq();

	/* Initialize the AP REFCLK Generic timer. */
	if (interrupt_id == IRQ_AP_REFCLK_BASE1_INTID) {
		init_ap_refclk_timer();
	}

	return sp_success(own_id, test_source, 0);
}

struct ffa_value sp_twdog_cmd(ffa_id_t test_source, uint64_t time)
{
	ffa_id_t own_id = hf_vm_get_id();

	HFTEST_LOG("Starting TWDOG: %lu ms", time);
	twdog_refresh();
	twdog_start((time * ARM_SP805_TWDG_CLK_HZ) / 1000);

	return sp_success(own_id, test_source, time);
}

struct ffa_value sp_generic_timer_cmd(ffa_id_t test_source, uint64_t time_ms)
{
	ffa_id_t own_id = hf_vm_get_id();

	HFTEST_LOG("Starting Generic Timer: %lu ms", time_ms);
	program_ap_refclk_timer(time_ms);

	return sp_success(own_id, test_source, time_ms);
}

struct ffa_value sp_get_last_interrupt_cmd(ffa_id_t test_source)
{
	ffa_id_t own_id = hf_vm_get_id();

	return sp_success(own_id, test_source,
			  exception_handler_get_last_interrupt());
}

struct ffa_value sp_clear_last_interrupt_cmd(ffa_id_t test_source)
{
	ffa_id_t own_id = hf_vm_get_id();

	exception_handler_set_last_interrupt(HF_INVALID_INTID);
	return sp_success(own_id, test_source, 0);
}

static bool is_expected_sp_response(struct ffa_value ret,
				    uint32_t expected_resp, uint32_t arg)
{
	if (ret.func != FFA_MSG_SEND_DIRECT_RESP_32) {
		return false;
	}

	if (sp_resp_value(ret) != expected_resp || ret.arg4 != arg) {
		HFTEST_LOG("Expected response %x and %x; Obtained %x and %lx",
			   expected_resp, arg, sp_resp_value(ret), ret.arg4);
		return false;
	}

	return true;
}

static inline bool mask_interrupts(uint32_t options)
{
	return ((options & OPTIONS_MASK_INTERRUPTS) != 0);
}

static inline bool yield_direct_request(uint32_t options)
{
	return ((options & OPTIONS_YIELD_DIR_REQ) != 0);
}

struct ffa_value sp_sleep_cmd(ffa_id_t source, uint32_t sleep_ms,
			      uint32_t options, uint64_t func)
{
	uint64_t time_lapsed;
	ffa_id_t own_id = hf_vm_get_id();

	if (mask_interrupts(options)) {
		/* Mask virtual interrupts. */
		sp_disable_irq();
	}

	if (yield_direct_request(options)) {
		ffa_yield();
	}

	HFTEST_LOG("Request to sleep %x for %ums", own_id, sleep_ms);

	time_lapsed = sp_sleep_active_wait(sleep_ms);

	/* Lapsed time should be at least equal to sleep time. */
	HFTEST_LOG("Sleep complete: %lu", time_lapsed);

	if (func == FFA_MSG_SEND_DIRECT_REQ2_64) {
		uint64_t msg[] = {0, time_lapsed};
		return ffa_msg_send_direct_resp2(own_id, source,
						 (const uint64_t *)&msg,
						 ARRAY_SIZE(msg));
	}
	return sp_success(own_id, source, time_lapsed);
}

static inline bool get_hint_interrupted(uint32_t options)
{
	return ((options & OPTIONS_HINT_INTERRUPTED) != 0);
}

struct ffa_value sp_fwd_sleep_cmd(ffa_id_t source, uint32_t sleep_ms,
				  ffa_id_t fwd_dest, uint32_t options)
{
	struct ffa_value ffa_ret;
	ffa_id_t own_id = hf_vm_get_id();
	bool fwd_dest_interrupted = false;
	bool hint_interrupted = false;

	HFTEST_LOG("VM%x requested %x to sleep for %ums", source, fwd_dest,
		   sleep_ms);

	ffa_ret = sp_sleep_cmd_send(own_id, fwd_dest, sleep_ms, options);

	if (get_hint_interrupted(options)) {
		hint_interrupted = true;
	}

	/*
	 * The target of the direct request could be pre-empted any number of
	 * times. Moreover, the target SP may or may not support managed exit.
	 * Hence, the target is allocated cpu cycles in this while loop.
	 */
	while ((ffa_ret.func == FFA_INTERRUPT_32) ||
	       is_expected_sp_response(ffa_ret, HF_MANAGED_EXIT_INTID, 0)) {
		fwd_dest_interrupted = true;

		if (ffa_ret.func == FFA_INTERRUPT_32) {
			/* Received FFA_INTERRUPT_32 in blocked state. */
			HFTEST_LOG(
				"Processing FFA_INTERRUPT_32 while"
				" blocked on direct response");

			ffa_ret = ffa_run(fwd_dest, ffa_vcpu_index(ffa_ret));
		} else {
			/*
			 * Destination sent managed exit response. Allocate
			 * dummy cycles through direct request message to
			 * destination SP.
			 */
			HFTEST_LOG("SP%x: received Managed Exit as response",
				   own_id);
			ffa_ret = sp_resume_after_managed_exit_send(own_id,
								    fwd_dest);
		}
	}

	if (hint_interrupted && !fwd_dest_interrupted) {
		HFTEST_LOG(
			"Forwarded destination of the sleep command was not"
			" interrupted as anticipated");
		return sp_error(own_id, source, 0);
	}

	if (ffa_ret.func != FFA_MSG_SEND_DIRECT_RESP_32) {
		HFTEST_LOG("Encountered error in SP_FWD_SLEEP_CMD response");
		return sp_error(own_id, source, 0);
	}

	if (sp_resp_value(ffa_ret) < sleep_ms) {
		HFTEST_LOG("Request returned: %u ms!", sp_resp_value(ffa_ret));
		return sp_error(own_id, source, 0);
	}

	return sp_success(own_id, source, 0);
}

struct ffa_value sp_yield_secure_interrupt_handling_cmd(ffa_id_t source,
							bool yield)
{
	ffa_id_t own_id = hf_vm_get_id();

	yield_while_handling_sec_interrupt = yield;
	return sp_success(own_id, source, 0);
}

struct ffa_value sp_route_interrupt_to_target_vcpu_cmd(
	ffa_id_t source, ffa_vcpu_index_t target_vcpu_id, uint32_t int_id)
{
	ffa_id_t own_id = hf_vm_get_id();

	/* Change target vCPU for the trusted watchdog interrupt. */
	if (hf_interrupt_reconfigure_target_cpu(int_id, target_vcpu_id) == 0) {
		return sp_success(own_id, source, 0);
	}

	HFTEST_LOG(
		"Request to route trusted wdog interrupt to target vCPU "
		"denied\n");
	return sp_error(own_id, source, 0);
}

struct ffa_value sp_prepare_spmc_call_chain_cmd(ffa_id_t source, bool initiate)
{
	ffa_id_t own_id = hf_vm_get_id();

	initiate_spmc_call_chain = initiate;
	return sp_success(own_id, source, 0);
}

struct ffa_value sp_prepare_preempt_interrupt_handling_cmd(ffa_id_t source,
							   bool preempt)
{
	ffa_id_t own_id = hf_vm_get_id();

	preempt_interrupt_handling = preempt;
	return sp_success(own_id, source, 0);
}
