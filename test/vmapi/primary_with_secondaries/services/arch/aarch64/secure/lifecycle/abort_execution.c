/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/mmio.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "sp_helpers.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

#define ILLEGAL_ADDR 5

static void irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();

	if (intid == IRQ_TWDOG_INTID) {
		HFTEST_LOG("Received Trusted WatchDog Interrupt: %u.", intid);
		twdog_stop();
	} else if (intid == HF_NOTIFICATION_PENDING_INTID) {
		/* RX buffer full notification. */
		HFTEST_LOG("Received notification pending interrupt %u.",
			   intid);
	} else {
		panic("Invalid interrupt received: %u\n", intid);
	}
}

TEST_SERVICE(sp_ffa_abort_dir_req)
{
	struct ffa_value args;

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_abort_32(0);

	FAIL("Not expected to return after FFA_ABORT");
}
