/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/abi.h"
#include "hf/call.h"
#include "hf/ffa.h"

#include "gicv3.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

SET_UP(timer_secondary)
{
	gicv3_system_setup();

	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	SERVICE_SELECT(SERVICE_VM1, "timer", send_buffer);

	interrupt_enable(VIRTUAL_TIMER_IRQ, true);
	interrupt_set_edge_triggered(VIRTUAL_TIMER_IRQ, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();
}

TEAR_DOWN(timer_secondary)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

SET_UP(timer_secondary_ffa)
{
	gicv3_system_setup();

	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	SERVICE_SELECT(SERVICE_VM1, "timer_ffa_direct_msg", send_buffer);

	interrupt_enable(VIRTUAL_TIMER_IRQ, true);
	interrupt_set_edge_triggered(VIRTUAL_TIMER_IRQ, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();
}

TEAR_DOWN(timer_secondary_ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

static void timer_busywait_secondary(void)
{
	const char message[] = "loop 0099999";
	const char expected_response[] = "Got IRQ 03.";
	uint8_t response[sizeof(expected_response)];
	ffa_id_t sender;
	struct ffa_value ret;

	/* Let the secondary get started and wait for our message. */
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(ret.arg2, FFA_SLEEP_INDEFINITE);

	/* Send the message for the secondary to set a timer. */
	ret = send_indirect_message(HF_PRIMARY_VM_ID, SERVICE_VM1, send_buffer,
				    message, sizeof(message), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/*
	 * Let the secondary handle the message and set the timer. It will loop
	 * until the hardware interrupt fires, at which point we'll get and
	 * ignore the interrupt, and see a FFA_YIELD return code.
	 */
	dlog("running secondary after sending timer message.\n");
	last_interrupt_id = 0;
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_INTERRUPT_32);
	dlog("secondary yielded after receiving timer message\n");
	EXPECT_EQ(last_interrupt_id, VIRTUAL_TIMER_IRQ);

	/*
	 * Now that the timer has expired, when we call ffa_run again Hafnium
	 * should inject a virtual timer interrupt into the secondary, which
	 * should get it and respond.
	 */
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
	receive_indirect_message((void *)response, sizeof(response),
				 recv_buffer, &sender);
	EXPECT_EQ(
		memcmp(response, expected_response, sizeof(expected_response)),
		0);
	EXPECT_EQ(sender, SERVICE_VM1);
}

/**
 * Send a message to the interruptible VM, which will start a timer to interrupt
 * itself to send a response back.
 */
TEST(timer_secondary, busywait)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_busywait_secondary();
	timer_busywait_secondary();
}

static void timer_secondary(const char message[], uint64_t expected_code)
{
	const char expected_response[] = "Got IRQ 03.";
	size_t message_length = strnlen_s(message, 64) + 1;
	uint8_t response[sizeof(expected_response)];
	ffa_id_t sender;
	struct ffa_value ret;

	/* Let the secondary get started and wait for our message. */
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send the message for the secondary to set a timer. */
	ret = send_indirect_message(HF_PRIMARY_VM_ID, SERVICE_VM1, send_buffer,
				    message, message_length, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Let the secondary handle the message and set the timer. */
	last_interrupt_id = 0;
	ret = ffa_run(SERVICE_VM1, 0);

	/*
	 * There's a race for whether the secondary manages to block and switch
	 * to the primary before the hardware timer fires, so we need to handle
	 * three cases:
	 * 1. The (hardware) timer fires immediately, we get FFA_INTERRUPT.
	 * 2. The secondary blocks and switches back, we get expected_code until
	 *   the timer fires.
	 *  2a. The timer then expires while we are in the primary, so Hafnium
	 *   can inject the timer interrupt the next time we call ffa_run.
	 *  2b. The timer fires while the secondary is running, so we get
	 *   FFA_INTERRUPT as in case 1.
	 */

	if (ret.func != expected_code && ret.func != FFA_INTERRUPT_32) {
		FAIL("Expected run to return FFA_INTERRUPT or %#x, but "
		     "got %#x",
		     expected_code, ret.func);
	}

	/* Loop until the timer fires. */
	while (ret.func == expected_code) {
		/*
		 * This case happens if the secondary manages to block and
		 * switch to the primary before the timer fires.
		 */
		dlog("Primary looping until timer fires\n");
		if (expected_code == HF_FFA_RUN_WAIT_FOR_INTERRUPT ||
		    expected_code == FFA_MSG_WAIT_32) {
			EXPECT_NE(ret.arg2, FFA_SLEEP_INDEFINITE);
			dlog("%d ns remaining\n", ret.arg2);
		}
		ret = ffa_run(SERVICE_VM1, 0);
	}
	dlog("Primary done looping\n");

	if (ret.func == FFA_INTERRUPT_32) {
		/*
		 * This case happens if the (hardware) timer fires before the
		 * secondary blocks and switches to the primary, either
		 * immediately after setting the timer or during the loop above.
		 * Then we get the interrupt to the primary, ignore it, and see
		 * a FFA_INTERRUPT code from the ffa_run call, so we should
		 * call it again for the timer interrupt to be injected
		 * automatically by Hafnium.
		 */
		EXPECT_EQ(last_interrupt_id, VIRTUAL_TIMER_IRQ);
		dlog("Preempted by timer interrupt, running again\n");
		ffa_run(SERVICE_VM1, 0);
	}

	/* Once we wake it up it should get the timer interrupt and respond. */
	receive_indirect_message((void *)response, sizeof(response),
				 recv_buffer, &sender);
	EXPECT_EQ(
		memcmp(response, expected_response, sizeof(expected_response)),
		0);
	EXPECT_EQ(sender, SERVICE_VM1);
}

/**
 * Send a message to the interruptible VM, which will start a timer to interrupt
 * itself to send a response back. This test is run with both long and short
 * timer lengths, to try to cover both cases of the race for whether the timer
 * fires before or after the secondary VM blocks and switches back to the
 * primary.
 */
TEST(timer_secondary, wfi_short)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_secondary("WFI  0000001", HF_FFA_RUN_WAIT_FOR_INTERRUPT);
	timer_secondary("WFI  0000001", HF_FFA_RUN_WAIT_FOR_INTERRUPT);
}

TEST(timer_secondary, wfi_long)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_secondary("WFI  0899999", HF_FFA_RUN_WAIT_FOR_INTERRUPT);
	timer_secondary("WFI  0899999", HF_FFA_RUN_WAIT_FOR_INTERRUPT);
}

TEST(timer_secondary, wfe_short)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_secondary("WFE  0000001", FFA_YIELD_32);
	timer_secondary("WFE  0000001", FFA_YIELD_32);
}

TEST(timer_secondary, wfe_long)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_secondary("WFE  0899999", FFA_YIELD_32);
	timer_secondary("WFE  0899999", FFA_YIELD_32);
}

TEST(timer_secondary, receive_short)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_secondary("RECV 0000001", FFA_MSG_WAIT_32);
	timer_secondary("RECV 0000001", FFA_MSG_WAIT_32);
}

TEST(timer_secondary, receive_long)
{
	/*
	 * Run the test twice in a row, to check that the state doesn't get
	 * messed up.
	 */
	timer_secondary("RECV 0899999", FFA_MSG_WAIT_32);
	timer_secondary("RECV 0899999", FFA_MSG_WAIT_32);
}

/**
 * Set the timer for a very long time, and expect that it doesn't fire.
 */
TEST(timer_secondary, wfi_very_long)
{
	const char message[] = "WFI  9999999";
	size_t message_length = strnlen_s(message, 64) + 1;
	struct ffa_value ret;

	/* Let the secondary get started and wait for our message. */
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(ret.arg2, FFA_SLEEP_INDEFINITE);

	/* Send the message for the secondary to set a timer. */
	ret = send_indirect_message(HF_PRIMARY_VM_ID, SERVICE_VM1, send_buffer,
				    message, message_length, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/*
	 * Let the secondary handle the message and set the timer.
	 */
	last_interrupt_id = 0;
	for (int i = 0; i < 20; ++i) {
		ret = ffa_run(SERVICE_VM1, 0);
		EXPECT_EQ(ret.func, HF_FFA_RUN_WAIT_FOR_INTERRUPT);
		dlog("Primary looping until timer fires; %d ns "
		     "remaining\n",
		     ret.arg2);
	}
}

/**
 * While handling a direct message, the secondary vCPU sets a timer to expire
 * far in the future. The primary should get the direct response, then call
 * FFA_RUN and get back an FFA_MSG_WAIT with arg2 != FFA_SLEEP_INDEFINITE.
 */
TEST(timer_secondary_ffa, timer_ffa_direct_msg_timeout)
{
	struct ffa_value res;

	/* Let the secondary get started and wait for a message. */
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	/* Unblock secondary VM so it starts a long timer */
	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 2);

	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_NE(res.arg2, FFA_SLEEP_INDEFINITE);
}
