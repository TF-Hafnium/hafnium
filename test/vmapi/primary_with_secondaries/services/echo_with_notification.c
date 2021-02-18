/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "test/hftest.h"

static void irq(void)
{
	hf_interrupt_get();
}

static void wait_for_vm(uint32_t vmid)
{
	for (;;) {
		int64_t w = hf_mailbox_writable_get();
		if (w == vmid) {
			return;
		}

		if (w == -1) {
			interrupt_wait();
			arch_irq_enable();
			arch_irq_disable();
		}
	}
}

TEST_SERVICE(echo_with_notification)
{
	exception_setup(irq, NULL);
	hf_interrupt_enable(HF_MAILBOX_WRITABLE_INTID, true,
			    INTERRUPT_TYPE_IRQ);

	/* Loop, echo messages back to the sender. */
	for (;;) {
		void *send_buf = SERVICE_SEND_BUFFER();
		void *recv_buf = SERVICE_RECV_BUFFER();
		struct ffa_value ret = ffa_msg_wait();
		ffa_vm_id_t target_vm_id = ffa_msg_send_receiver(ret);
		ffa_vm_id_t source_vm_id = ffa_msg_send_sender(ret);

		memcpy_s(send_buf, FFA_MSG_PAYLOAD_MAX, recv_buf,
			 ffa_msg_send_size(ret));

		while (ffa_msg_send(target_vm_id, source_vm_id,
				    ffa_msg_send_size(ret), FFA_MSG_SEND_NOTIFY)
			       .func != FFA_SUCCESS_32) {
			wait_for_vm(source_vm_id);
		}

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	}
}
