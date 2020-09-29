/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"

/*
 * Secondary VM that enables an interrupt, disables interrupts globally, and
 * calls WFI.
 */

static void irq(void)
{
	uint32_t interrupt_id = hf_interrupt_get();
	FAIL("Unexpected secondary IRQ %d from current", interrupt_id);
}

TEST_SERVICE(wfi)
{
	int32_t i;
	const char message[] = "Done waiting";

	exception_setup(irq, NULL);
	arch_irq_disable();
	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true);

	for (i = 0; i < 10; ++i) {
		interrupt_wait();
	}

	memcpy_s(SERVICE_SEND_BUFFER(), SPCI_MSG_PAYLOAD_MAX, message,
		 sizeof(message));

	spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(message), 0);
}
