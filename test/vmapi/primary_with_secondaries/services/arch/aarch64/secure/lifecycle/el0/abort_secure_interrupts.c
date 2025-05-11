/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/ffa.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "../smc.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

TEST_SERVICE(sp_ffa_abort_sec_int_handling)
{
	struct hftest_context *ctx = hftest_get_context();
	void *recv_buf = SERVICE_RECV_BUFFER();
	uint32_t delay;
	struct ffa_value res;

	/*
	 * Map MMIO address space of peripherals (such as secure
	 * watchdog timer) described as device region nodes in partition
	 * manifest.
	 */
	hftest_map_device_regions(ctx);

	/* Enable the Secure Watchdog timer interrupt. */
	EXPECT_EQ(hf_interrupt_enable(IRQ_TWDOG_INTID, true, 0), 0);

	receive_indirect_message(&delay, sizeof(delay), recv_buf);

	/* Start the secure Watchdog timer. */
	HFTEST_LOG("Starting TWDOG: %u ms", delay);
	twdog_refresh();
	twdog_start((delay * ARM_SP805_TWDG_CLK_HZ) / 1000);

	/* Give back control to PVM. */
	res = ffa_msg_wait();

	/* SPMC signals the secure interrupt through FFA_INTERRUPT interface. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	twdog_stop();

	/* Abort execution voluntarily. */
	ffa_abort_32(0);

	/*
	 * Execution should never reach here as SP aborts while handling
	 * secure interrupt.
	 */
	FAIL("Not expected to reach here");
}
