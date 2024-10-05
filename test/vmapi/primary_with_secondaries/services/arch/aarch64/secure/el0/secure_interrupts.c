/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

#define ITERATIONS_PER_MS 15000

static inline void sp_wait_loop(uint32_t ms)
{
	uint64_t iterations = (uint64_t)ms * ITERATIONS_PER_MS;

	for (volatile uint64_t loop = 0; loop < iterations; loop++) {
		/* Wait */
	}
}

TEST_SERVICE(sec_interrupt_preempt_msg)
{
	uint32_t delay;
	struct ffa_value res;
	ffa_id_t echo_sender;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct hftest_context *ctx = hftest_get_context();

	dlog_verbose("sec_interrupt_preempt_msg from an S-EL0 partition.");

	/*
	 * Map MMIO address space of peripherals (such as secure
	 * watchdog timer) described as device region nodes in partition
	 * manifest.
	 */
	hftest_map_device_regions(ctx);

	/* Enable the Secure Watchdog timer interrupt. */
	EXPECT_EQ(hf_interrupt_enable(IRQ_TWDOG_INTID, true, 0), 0);

	receive_indirect_message((void *)&delay, sizeof(delay), recv_buf,
				 &echo_sender);

	HFTEST_LOG("Message received: %#x", delay);

	/* Echo message back. */
	send_indirect_message(hf_vm_get_id(), echo_sender, send_buf, &delay,
			      sizeof(delay), 0);

	/* Start the secure Watchdog timer. */
	HFTEST_LOG("Starting TWDOG: %u ms", delay);
	twdog_refresh();
	twdog_start((delay * ARM_SP805_TWDG_CLK_HZ) / 1000);

	/* Wait for the interrupt to trigger. */
	sp_wait_loop(delay + 50);

	/* Give back control to PVM. */
	res = ffa_msg_wait();

	/* SPMC signals the secure interrupt through FFA_INTERRUPT interface. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/* S-EL0 partitions require this to be disabled after the FF-A call. */
	ASSERT_EQ(hf_interrupt_deactivate(IRQ_TWDOG_INTID), 0);

	/* Secure interrupt has been serviced by now. Relinquish cycles. */
	ffa_msg_wait();
}
