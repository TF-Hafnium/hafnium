/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/timer.h"

#include "hf/arch/irq.h"
#include "hf/arch/vm/events.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "common.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * Secondary VM that sets timers in response to messages, and sends messages
 * back when they fire.
 */

static volatile bool timer_fired = false;

static void irq_current(void)
{
	uint32_t interrupt_id = hf_interrupt_get();
	char buffer[] = "Got IRQ xx.";
	int size = sizeof(buffer);
	dlog("secondary IRQ %d from current\n", interrupt_id);
	if (interrupt_id == HF_VIRTUAL_TIMER_INTID) {
		timer_fired = true;
	}
	buffer[8] = '0' + interrupt_id / 10;
	buffer[9] = '0' + interrupt_id % 10;
	memcpy_s(SERVICE_SEND_BUFFER(), FFA_MSG_PAYLOAD_MAX, buffer, size);
	ffa_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, size, 0);
	dlog("secondary IRQ %d ended\n", interrupt_id);
	event_send_local();
}

TEST_SERVICE(timer)
{
	exception_setup(irq_current, NULL);
	hf_interrupt_enable(HF_VIRTUAL_TIMER_INTID, true);
	arch_irq_enable();

	for (;;) {
		uint8_t *message = (uint8_t *)SERVICE_RECV_BUFFER();
		bool wfi;
		bool wfe;
		bool receive;
		bool disable_interrupts;
		uint32_t ticks;
		struct ffa_value ret = mailbox_receive_retry();

		if (ffa_msg_send_sender(ret) != HF_PRIMARY_VM_ID ||
		    ffa_msg_send_size(ret) != sizeof("**** xxxxxxx")) {
			FAIL("Got unexpected message from VM %d, size %d.\n",
			     ffa_msg_send_sender(ret), ffa_msg_send_size(ret));
		}

		/*
		 * Start a timer to send the message back: enable it and
		 * set it for the requested number of ticks.
		 */
		wfi = memcmp(message, "WFI ", 4) == 0;
		wfe = memcmp(message, "WFE ", 4) == 0;
		receive = memcmp(message, "RECV", 4) == 0;
		disable_interrupts = wfi || receive;
		ticks = (message[5] - '0') * 1000000 +
			(message[6] - '0') * 100000 +
			(message[7] - '0') * 10000 + (message[8] - '0') * 1000 +
			(message[9] - '0') * 100 + (message[10] - '0') * 10 +
			(message[11] - '0');

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

		dlog("Starting timer for %d ticks.\n", ticks);

		if (disable_interrupts) {
			arch_irq_disable();
		}

		timer_set(ticks);
		timer_start();
		dlog("Waiting for timer...\n");

		/* Wait for the timer interrupt. */
		if (wfi) {
			interrupt_wait();
		} else if (wfe) {
			while (!timer_fired) {
				event_wait();
			}
		} else if (receive) {
			struct ffa_value res = ffa_msg_wait();

			EXPECT_FFA_ERROR(res, FFA_INTERRUPTED);
		} else {
			/* Busy wait until the timer fires. */
			while (!timer_fired) {
			}
		}

		if (disable_interrupts) {
			arch_irq_enable();
		}

		EXPECT_TRUE(timer_fired);
		timer_fired = false;
		dlog("Done waiting.\n");
	}
}

/**
 * Secondary VM handles a direct message request, starts a long timer,
 * and sends a direct message response.
 */
TEST_SERVICE(timer_ffa_direct_msg)
{
	struct ffa_value res;

	exception_setup(irq_current, NULL);
	hf_interrupt_enable(HF_VIRTUAL_TIMER_INTID, true);
	arch_irq_enable();

	res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	dlog("Starting long timer\n");
	timer_set(9999999);
	timer_start();

	ffa_msg_send_direct_resp(ffa_msg_send_receiver(res),
				 ffa_msg_send_sender(res), 2, 0, 0, 0, 0);
}
