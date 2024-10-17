/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sp_helpers.h"

#include "hf/arch/vm/timer.h"

#include "ap_refclk_generic_timer.h"
#include "partition_services.h"
#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "twdog.h"

#define ITERATIONS_PER_MS 15000

extern bool yield_while_handling_sec_interrupt;
extern bool preempt_interrupt_handling;
extern bool initiate_spmc_call_chain;

/*
 * This variable is set by the request that processes the arch timer commands
 * from the PVM.
 */
extern uint32_t periodic_timer_ms;

void sp_enable_irq(void)
{
}

void sp_disable_irq(void)
{
}

struct ffa_value handle_interrupt(struct ffa_value res)
{
	uint32_t intid;
	struct ffa_value ffa_ret;
	ffa_id_t own_id = hf_vm_get_id();

	/*
	 * Received FFA_INTERRUPT in waiting state with interrupt ID
	 * passed in arg2.
	 */
	intid = hf_interrupt_get();

	ASSERT_EQ(res.arg1, 0);
	ASSERT_EQ(res.arg2, intid);

	switch (intid) {
	case IRQ_TWDOG_INTID: {
		/*
		 * Interrupt triggered due to Trusted watchdog timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		HFTEST_LOG("S-EL0 vIRQ: Trusted WatchDog timer stopped: %u",
			   intid);
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
		break;
	}
	case IRQ_AP_REFCLK_BASE1_INTID: {
		HFTEST_LOG("S-EL0 vIRQ: AP_REFCLK timer stopped: %u", intid);
		cancel_ap_refclk_timer();
		break;
	}
	case HF_VIRTUAL_TIMER_INTID: {
		/* Disable the EL1 arch timer. */
		timer_disable();

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
	return ffa_msg_wait();
}

void sp_register_secondary_ep(struct hftest_context *ctx)
{
	(void)ctx;
}
