/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "vmapi/hf/call.h"

#include "interrupt_status.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

#define ITERATIONS_PER_MS 15000
#define TWDOG_DELAY 50

static inline uint64_t physicalcounter_read(void)
{
	isb();
	return read_msr(cntpct_el0);
}

static inline uint64_t sp_wait(uint32_t ms)
{
	uint64_t timer_freq = read_msr(cntfrq_el0);

	uint64_t time1 = physicalcounter_read();
	volatile uint64_t time2 = time1;

	while ((time2 - time1) < ((ms * timer_freq) / 1000U)) {
		time2 = physicalcounter_read();
	}

	return ((time2 - time1) * 1000) / timer_freq;
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
	sp_wait(delay + 50);

	/* Give back control to PVM. */
	res = ffa_msg_wait();

	/* SPMC signals the secure interrupt through FFA_INTERRUPT interface. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/* S-EL0 partitions require this to be disabled after the FF-A call. */
	ASSERT_EQ(hf_interrupt_deactivate(IRQ_TWDOG_INTID), 0);

	/* Secure interrupt has been serviced by now. Relinquish cycles. */
	ffa_msg_wait();
}

TEST_SERVICE(send_direct_req_yielded_and_resumed)
{
	struct ffa_value ret;
	ffa_id_t target_vm_id;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	const uint32_t msg[] = {TWDOG_DELAY, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};

	receive_indirect_message((void *)&target_vm_id, sizeof(target_vm_id),
				 recv_buf, NULL);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Get the shared page used for interrupt status coordination and track
	 * it. */
	hftest_interrupt_status_page_setup(recv_buf, send_buf);
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_RESET);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	ret = ffa_msg_send_direct_req(hf_vm_get_id(), target_vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(ret.func, FFA_YIELD_32);

	EXPECT_EQ(hftest_interrupt_status_get(), INTR_PROGRAMMED);

	/* Wait for TWDOG secure physical interrupt to trigger. */
	sp_wait(TWDOG_DELAY + 5);
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_PROGRAMMED);

	ret = ffa_run(target_vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_SERVICED);

	ffa_msg_wait();
	FAIL("Not expected to reach here");
}

TEST_SERVICE(yield_direct_req_service_twdog_int)
{
	struct ffa_value ret;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct hftest_context *ctx = hftest_get_context();

	/*
	 * Map MMIO address space of peripherals (such as secure
	 * watchdog timer) described as device region nodes in partition
	 * manifest.
	 */
	hftest_map_device_regions(ctx);

	/* Enable the Secure Watchdog timer interrupt. */
	EXPECT_EQ(hf_interrupt_enable(IRQ_TWDOG_INTID, true, 0), 0);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Get the shared page used for interrupt status coordination and track
	 * it. */
	hftest_interrupt_status_page_setup(recv_buf, send_buf);

	/*
	 * Ensure the status of the interrupt is correct before the test begins.
	 */
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_RESET);

	ret = ffa_msg_wait();

	/* The companion SP sends a direct request message. */
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);

	/* Program the trusted watchdog timer and yield to companion SP. */
	HFTEST_LOG("Start TWDOG timer with a delay of %lu", ret.arg3);
	twdog_start((ret.arg3 * ARM_SP805_TWDG_CLK_HZ) / 1000);

	hftest_interrupt_status_set(INTR_PROGRAMMED);

	/* Yield the direct request thereby moving to BLOCKED state. */
	ffa_yield();

	HFTEST_LOG("Completing the direct response");
	ret = ffa_msg_send_direct_resp(ffa_receiver(ret), ffa_sender(ret),
				       ret.arg3, ret.arg4, ret.arg5, ret.arg6,
				       ret.arg7);

	/* SPMC signals the secure interrupt through FFA_INTERRUPT interface. */
	EXPECT_EQ(ret.func, FFA_INTERRUPT_32);

	/* S-EL0 partitions require this to be disabled after the FF-A call. */
	ASSERT_EQ(hf_interrupt_deactivate(IRQ_TWDOG_INTID), 0);
	twdog_stop();

	/* Update the status of interrupt as serviced. */
	hftest_interrupt_status_set(INTR_SERVICED);

	/* Secure interrupt has been serviced by now. Relinquish cycles. */
	ffa_msg_wait();
	FAIL("Not expected to reach here");
}
