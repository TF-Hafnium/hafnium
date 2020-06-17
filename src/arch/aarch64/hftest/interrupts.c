/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include <stdint.h>

#include "hf/dlog.h"

#include "msr.h"
#include "test/hftest.h"

extern uint8_t vector_table_el1;
static void (*irq_callback)(void);
static bool (*exception_callback)(void);

/**
 * Handles an IRQ at the current exception level.
 *
 * Returns false so that the value of elr_el1 is restored from the stack, in
 * case there are nested exceptions.
 */
bool irq_current(void)
{
	if (irq_callback != NULL) {
		irq_callback();
	} else {
		FAIL("Got unexpected interrupt.\n");
	}

	return false;
}

noreturn static bool default_sync_current_exception(void)
{
	uintreg_t esr = read_msr(esr_el1);
	uintreg_t elr = read_msr(elr_el1);

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

/**
 * Handles a synchronous exception at the current exception level.
 *
 * Returns true if the value of elr_el1 should be kept as-is rather than
 * restored from the stack. This enables exception handlers to indicate whether
 * they have changed the value of elr_el1 (e.g., to skip the faulting
 * instruction).
 */
bool sync_exception_current(void)
{
	if (exception_callback != NULL) {
		return exception_callback();
	}
	return default_sync_current_exception();
}

void exception_setup(void (*irq)(void), bool (*exception)(void))
{
	irq_callback = irq;
	exception_callback = exception;

	/* Set exception vector table. */
	write_msr(VBAR_EL1, &vector_table_el1);
}

void interrupt_wait(void)
{
	__asm__ volatile("wfi");
}
