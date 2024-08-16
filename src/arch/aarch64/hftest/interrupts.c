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
#include "sysregs_defs.h"
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
	uintreg_t ec = GET_ESR_EC(esr);

	switch (ec) {
	case EC_DATA_ABORT_SAME_EL: /* EC = 100101, Data abort. */
		dlog("Data abort: pc=%#lx, esr=%#lx, ec=%#lx", elr, esr, ec);
		if (!GET_ESR_FNV(esr)) {
			dlog(", far=%#lx", read_msr(far_el1));
		} else {
			dlog(", far=invalid");
		}

		dlog("\n");
		break;

	default:
		dlog("Unknown current sync exception pc=%#lx, esr=%#lx, "
		     "ec=%#lx\n",
		     elr, esr, ec);
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

void interrupts_enable(void)
{
	__asm__ volatile("msr DAIFClr, #0x3");
}

void interrupts_disable(void)
{
	__asm__ volatile("msr DAIFSet, #0x3");
}
