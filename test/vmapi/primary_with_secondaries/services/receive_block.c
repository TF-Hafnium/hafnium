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
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * Secondary VM that enables an interrupt, disables interrupts globally, and
 * calls hf_mailbox_receive with block=true but expects it to fail.
 */

static void irq(void)
{
	uint32_t interrupt_id = hf_interrupt_get();
	FAIL("Unexpected secondary IRQ %d from current", interrupt_id);
}

TEST_SERVICE(receive_block)
{
	int32_t i;
	const char message[] = "Done waiting";
	void* send_buf = SERVICE_SEND_BUFFER();
	ffa_id_t own_id = hf_vm_get_id();

	exception_setup(irq, NULL);
	arch_irq_disable();
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);

	for (i = 0; i < 10; ++i) {
		struct ffa_value res = ffa_msg_wait();
		EXPECT_FFA_ERROR(res, FFA_INTERRUPTED);
	}

	send_indirect_message(own_id, HF_PRIMARY_VM_ID, send_buf, message,
			      sizeof(message), 0);
	ffa_yield();
}
