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
#include "vmapi/hf/ffa.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"

/*
 * Secondary VM that sends messages in response to interrupts, and interrupts
 * itself when it receives a message.
 */

static void irq(void)
{
	uint32_t interrupt_id = hf_interrupt_get();
	if (interrupt_id == HF_INVALID_INTID) {
		return;
	}
	char buffer[] = "Got IRQ xx.";
	int size = sizeof(buffer);
	dlog("secondary IRQ %d from current\n", interrupt_id);
	buffer[8] = '0' + interrupt_id / 10;
	buffer[9] = '0' + interrupt_id % 10;
	memcpy_s(SERVICE_SEND_BUFFER(), FFA_MSG_PAYLOAD_MAX, buffer, size);
	ffa_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, size, 0);
	dlog("secondary IRQ %d ended\n", interrupt_id);
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
		 ffa_error_code(received) == FFA_INTERRUPTED);

	return received;
}

TEST_SERVICE(interruptible)
{
	ffa_id_t this_vm_id = hf_vm_get_id();
	void *recv_buf = SERVICE_RECV_BUFFER();

	hf_interrupt_enable(SELF_INTERRUPT_ID, true, INTERRUPT_TYPE_IRQ);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_B, true, INTERRUPT_TYPE_IRQ);

	for (;;) {
		const char ping_message[] = "Ping";
		const char enable_message[] = "Enable interrupt C";

		struct ffa_value ret = mailbox_receive_retry_v1_0();

		ASSERT_EQ(ret.func, FFA_MSG_SEND_32);
		if (ffa_sender(ret) == HF_PRIMARY_VM_ID &&
		    ffa_msg_send_size(ret) == sizeof(ping_message) &&
		    memcmp(recv_buf, ping_message, sizeof(ping_message)) == 0) {
			/* Interrupt ourselves */
			hf_interrupt_inject(this_vm_id, 0, SELF_INTERRUPT_ID);
		} else if (ffa_sender(ret) == HF_PRIMARY_VM_ID &&
			   ffa_msg_send_size(ret) == sizeof(enable_message) &&
			   memcmp(recv_buf, enable_message,
				  sizeof(enable_message)) == 0) {
			/* Enable interrupt ID C. */
			hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_C, true,
					    INTERRUPT_TYPE_IRQ);
		} else {
			dlog("Got unexpected message from VM %d, size %d.\n",
			     ffa_sender(ret), ffa_msg_send_size(ret));
			FAIL("Unexpected message");
		}
		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	}
}
