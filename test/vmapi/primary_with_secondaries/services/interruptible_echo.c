/*
 * Copyright 2019 The Hafnium Authors.
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

TEST_SERVICE(interruptible_echo)
{
	ffa_id_t own_id = hf_vm_get_id();

	exception_setup(irq, NULL);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);
	arch_irq_enable();
	EXPECT_EQ(irq_counter, 0);

	for (;;) {
		struct ffa_value res = ffa_msg_wait();
		void *send_buf = SERVICE_SEND_BUFFER();
		void *recv_buf = SERVICE_RECV_BUFFER();
		char response[sizeof("I\'ll see you again.")];
		ffa_id_t sender;

		ASSERT_EQ(res.func, FFA_RUN_32);
		EXPECT_EQ(irq_counter, 1);

		receive_indirect_message(response, sizeof(response), recv_buf,
					 &sender);

		send_indirect_message(own_id, HF_PRIMARY_VM_ID, send_buf,
				      response, sizeof(response), 0);
	}
}

/**
 * Secondary VM gets an interrupt while waiting for a direct
 * message request.
 */
TEST_SERVICE(interruptible_echo_direct_msg)
{
	struct ffa_value res;

	exception_setup(irq, NULL);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);
	arch_irq_enable();

	res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	EXPECT_EQ(irq_counter, 0);
	res = ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0,
				       0, 0, 0);
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

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

	exception_setup(irq, NULL);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);
	arch_irq_enable();

	EXPECT_EQ(irq_counter, 0);

	dlog("Secondary VM waits for a direct message request.\n");

	res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);
	EXPECT_EQ(irq_counter, 1);

	dlog("Secondary VM received direct message request and interrupt.\n");

	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0, 0, 0,
				 0);
}
