/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/timer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hf/arch/cpu.h"
#include "hf/arch/vm/timer.h"

#include "hf/addr.h"

#include "msr.h"
#include "sysregs.h"

#define CNTV_CTL_EL0_ENABLE (1u << 0)
#define CNTV_CTL_EL0_IMASK (1u << 1)
#define CNTV_CTL_EL0_ISTATUS (1u << 2)

/**
 * Sets the bit to mask virtual timer interrupts.
 */
void arch_timer_mask(struct arch_regs *regs)
{
	regs->peripherals.cntv_ctl_el0 |= CNTV_CTL_EL0_IMASK;
}

/**
 * Checks whether the virtual timer is enabled and its interrupt not masked.
 */
bool arch_timer_enabled(struct arch_regs *regs)
{
	uintreg_t cntv_ctl_el0 = regs->peripherals.cntv_ctl_el0;

	return (cntv_ctl_el0 & CNTV_CTL_EL0_ENABLE) &&
	       !(cntv_ctl_el0 & CNTV_CTL_EL0_IMASK);
}

/**
 * Converts a number of timer ticks to the equivalent number of nanoseconds.
 */
static uint64_t ticks_to_ns(uint64_t ticks)
{
	return (ticks * NANOS_PER_UNIT) / read_msr(cntfrq_el0);
}

/**
 * Returns the number of ticks remaining on the virtual timer as stored in
 * the given `arch_regs`, or 0 if it has already expired. This is undefined if
 * the timer is not enabled.
 */
static uint64_t arch_timer_remaining_ticks(struct arch_regs *regs)
{
	/*
	 * Calculate the value from the saved CompareValue (cntv_cval_el0) and
	 * the virtual count value.
	 */
	uintreg_t cntv_cval_el0 = regs->peripherals.cntv_cval_el0;
	uintreg_t cntvct_el0 = read_msr(cntvct_el0);

	if (cntv_cval_el0 >= cntvct_el0) {
		return cntv_cval_el0 - cntvct_el0;
	}

	return 0;
}

/**
 * Returns the number of nanoseconds remaining on the virtual timer as stored in
 * the given `arch_regs`, or 0 if it has already expired. This is undefined if
 * the timer is not enabled.
 */
uint64_t arch_timer_remaining_ns(struct arch_regs *regs)
{
	return ticks_to_ns(arch_timer_remaining_ticks(regs));
}

/**
 * Returns whether the timer is ready to fire: i.e. it is enabled, not masked,
 * and the condition is met.
 */
bool arch_timer_pending(struct arch_regs *regs)
{
	if (!arch_timer_enabled(regs)) {
		return false;
	}

	if (regs->peripherals.cntv_ctl_el0 & CNTV_CTL_EL0_ISTATUS) {
		return true;
	}

	if (arch_timer_remaining_ticks(regs) == 0) {
		/*
		 * This can happen even if the (stored) ISTATUS bit is not set,
		 * because time has passed between when the registers were
		 * stored and now.
		 */
		return true;
	}

	return false;
}
