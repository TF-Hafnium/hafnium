/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/types.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

volatile uint32_t irq_counter;

static void irq(void)
{
	/* Clear the interrupt. */
	hf_interrupt_get();

	irq_counter++;
}

/**
 * Try to receive a message from the mailbox, blocking if necessary, and
 * retrying if interrupted.
 */
static struct ffa_value mailbox_receive_retry_v1_0(void)
{
	struct ffa_value received;

	do {
		irq();
		received = ffa_msg_wait();
	} while (received.func == FFA_ERROR_32 &&
		 received.arg2 == FFA_INTERRUPTED);

	return received;
}

TEST_SERVICE(interruptible_echo)
{
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);

	EXPECT_EQ(irq_counter, 0);
	for (;;) {
		struct ffa_value res = mailbox_receive_retry_v1_0();
		void *message = SERVICE_SEND_BUFFER();
		void *recv_message = SERVICE_RECV_BUFFER();

		ASSERT_EQ(res.func, FFA_MSG_SEND_32);
		EXPECT_EQ(irq_counter, 1);
		memcpy_s(message, FFA_MSG_PAYLOAD_MAX, recv_message,
			 ffa_msg_send_size(res));

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
		ffa_msg_send(SERVICE_VM1, HF_PRIMARY_VM_ID,
			     ffa_msg_send_size(res), 0);
	}
}

/**
 * Secondary VM gets an interrupt while waiting for a direct
 * message request.
 */
TEST_SERVICE(interruptible_echo_direct_msg)
{
	struct ffa_value res;

	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);

	res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	EXPECT_EQ(irq_counter, 0);
	res = ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0,
				       0, 0, 0);
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	irq();

	EXPECT_EQ(irq_counter, 1);

	/* Wait for another direct message request */
	res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 3);

	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 4, 0, 0, 0,
				 0);
}

/**
 * The Secondary VM waits for a direct message request. It receives both
 * a direct message request and an interrupt which it immediately services.
 * Then it replies straight with a direct message response.
 */
TEST_SERVICE(interruptible_echo_direct_msg_with_interrupt)
{
	struct ffa_value res;

	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);

	EXPECT_EQ(irq_counter, 0);

	dlog("Secondary VM waits for a direct message request.\n");

	res = mailbox_receive_retry_v1_0();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);
	EXPECT_EQ(irq_counter, 1);

	dlog("Secondary VM received direct message request and interrupt.\n");

	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0, 0, 0,
				 0);
}
