/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sp_helpers.h"

#include "partition_services.h"
#include "sp805.h"
#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"

#define ITERATIONS_PER_MS 15000

extern bool yield_while_handling_sec_interrupt;

uint64_t sp_sleep_active_wait(uint32_t ms)
{
	sp_wait_loop(ms * ITERATIONS_PER_MS);
	return ms;
}

void sp_enable_irq(void)
{
}

struct ffa_value handle_ffa_interrupt(struct ffa_value res)
{
	uint32_t intid;

	/*
	 * Received FFA_INTERRUPT in waiting state with interrupt ID
	 * passed in arg2.
	 */
	intid = hf_interrupt_get();

	ASSERT_EQ(intid, IRQ_TWDOG_INTID);
	ASSERT_EQ(res.arg1, 0);
	ASSERT_EQ(res.arg2, intid);

	/*
	 * Interrupt triggered due to Trusted watchdog timer expiry.
	 * Clear the interrupt and stop the timer.
	 */
	HFTEST_LOG("S-EL0 vIRQ: Trusted WatchDog timer stopped: %u", intid);
	sp805_twdog_stop();

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

struct ffa_value handle_ffa_run(struct ffa_value res)
{
	HFTEST_LOG_FAILURE();
	HFTEST_LOG(HFTEST_LOG_INDENT "0x%x is not a valid function\n",
		   res.func);
	abort();
}
