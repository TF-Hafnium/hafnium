/*
 * Copyright 2021 The Hafnium Authors.
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
	char buffer[] = "Got IRQ xx.";
	int size = sizeof(buffer);
	ffa_id_t own_id = hf_vm_get_id();

	dlog("secondary IRQ %d from current\n", interrupt_id);
	buffer[8] = '0' + interrupt_id / 10;
	buffer[9] = '0' + interrupt_id % 10;

	send_indirect_message(own_id, HF_PRIMARY_VM_ID, SERVICE_SEND_BUFFER(),
			      buffer, size, 0);
	dlog("secondary IRQ %d ended\n", interrupt_id);
	ffa_yield();
}

TEST_SERVICE(interruptible)
{
	ffa_id_t this_vm_id = hf_vm_get_id();
	void *recv_buf = SERVICE_RECV_BUFFER();

	exception_setup(irq, NULL);
	hf_interrupt_enable(SELF_INTERRUPT_ID, true, INTERRUPT_TYPE_IRQ);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_B, true, INTERRUPT_TYPE_IRQ);
	arch_irq_enable();

	for (;;) {
		const char ping_message[] = "Ping";
		const char enable_message[] = "Enable interrupt C";
		/* Allocate for the longest of the above two messages. */
		char response[sizeof(enable_message) + 1];
		struct ffa_partition_rxtx_header header;
		ffa_id_t sender;

		mailbox_receive_retry(response, sizeof(response), recv_buf,
				      &header);

		sender = ffa_rxtx_header_sender(&header);
		if (sender == HF_PRIMARY_VM_ID &&
		    header.size == sizeof(ping_message) &&
		    memcmp(response, ping_message, sizeof(ping_message)) == 0) {
			/* Interrupt ourselves */
			hf_interrupt_inject(this_vm_id, 0, SELF_INTERRUPT_ID);
		} else if (sender == HF_PRIMARY_VM_ID &&
			   header.size == sizeof(enable_message) &&
			   memcmp(response, enable_message,
				  sizeof(enable_message)) == 0) {
			/* Enable interrupt ID C. */
			hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_C, true,
					    INTERRUPT_TYPE_IRQ);
		} else {
			dlog("Got unexpected message from VM %d, size %d.\n",
			     sender, header.size);
			FAIL("Unexpected message");
		}
	}
}
