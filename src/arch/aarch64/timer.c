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

/*
 * As part of support for arch timer functionality, Hafnium exposes partitions
 * to EL1 Physical Timer (but traps and emulates the access behind the scenes
 * using host timer).
 */
#define CNTx_CTL_EL0_ENABLE (UINT32_C(1) << 0)
#define CNTx_CTL_EL0_IMASK (UINT32_C(1) << 1)
#define CNTx_CTL_EL0_ISTATUS (UINT32_C(1) << 2)

/**
 * Checks whether the arch timer is enabled and its interrupt not masked.
 */
bool arch_timer_enabled(struct arch_regs *regs)
{
	uintreg_t cntx_ctl_el0 = regs->arch_timer.ctl;

	return (cntx_ctl_el0 & CNTx_CTL_EL0_ENABLE) &&
	       !(cntx_ctl_el0 & CNTx_CTL_EL0_IMASK);
}

/**
 * Converts a number of timer ticks to the equivalent number of nanoseconds.
 */
static uint64_t ticks_to_ns(uint64_t ticks)
{
	return (ticks * NANOS_PER_UNIT) / read_msr(cntfrq_el0);
}

/**
 * Returns the number of ticks remaining on the arch timer as stored in
 * the given `arch_regs`, or 0 if it has already expired. This is undefined if
 * the timer is not enabled.
 */
static uint64_t arch_timer_remaining_ticks(struct arch_regs *regs)
{
	/*
	 * Calculate the value from the saved CompareValue (cntx_cval_el0) and
	 * the system count value.
	 */
	uintreg_t cntx_cval_el0 = regs->arch_timer.cval;

	/*
	 * Arm ARM recommends the use of ISB before reading CNTPCT_EL0 since
	 * it could be read out of order. However, we skip ISB given the
	 * performance overhead associated with it.
	 * This does not have an adverse effect on timer functionality as in
	 * the worst case this function could return a small non-zero value
	 * even though the timer deadline has expired which is still fine.
	 */
	uintreg_t cntpct_el0 = read_msr(cntpct_el0);

	if (cntx_cval_el0 >= cntpct_el0) {
		return cntx_cval_el0 - cntpct_el0;
	}

	return 0;
}

/**
 * Returns the number of nanoseconds remaining on the arch timer as stored in
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
bool arch_timer_expired(struct arch_regs *regs)
{
	if (!arch_timer_enabled(regs)) {
		return false;
	}

	if ((regs->arch_timer.ctl & CNTx_CTL_EL0_ISTATUS) != 0U) {
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
