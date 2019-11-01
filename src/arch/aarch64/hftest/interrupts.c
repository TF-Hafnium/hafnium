/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/arch/vm/interrupts.h"

#include <stdint.h>

#include "hf/dlog.h"

#include "msr.h"

extern uint8_t vector_table_el1;
static void (*irq_callback)(void);

void irq_current(void)
{
	if (irq_callback != NULL) {
		irq_callback();
	}
}

void exception_setup(void (*irq)(void))
{
	irq_callback = irq;

	/* Set exception vector table. */
	write_msr(VBAR_EL1, &vector_table_el1);
}

void sync_current_exception(uintreg_t esr, uintreg_t elr)
{
	switch (esr >> 26) {
	case 0x25: /* EC = 100101, Data abort. */
		dlog("Data abort: pc=%#x, esr=%#x, ec=%#x", elr, esr,
		     esr >> 26);
		if (!(esr & (1U << 10))) { /* Check FnV bit. */
			dlog(", far=%#x", read_msr(far_el1));
		} else {
			dlog(", far=invalid");
		}

		dlog("\n");
		break;

	default:
		dlog("Unknown current sync exception pc=%#x, esr=%#x, "
		     "ec=%#x\n",
		     elr, esr, esr >> 26);
	}

	for (;;) {
		/* do nothing */
	}
}

void interrupt_wait(void)
{
	__asm__ volatile("wfi");
}
