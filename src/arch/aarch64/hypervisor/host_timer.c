/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/host_timer.h"

#include "hf/arch/gicv3.h"

#include "hf/plat/interrupts.h"

#include "msr.h"
#include "sysregs.h"

/**
 * Disable EL2/S-EL2 physical timer.
 */
void host_timer_disable(void)
{
#if SECURE_WORLD == 1
	write_msr(cnthps_ctl_el2, 0);
#else
	write_msr(cnthp_ctl_el2, 0);
#endif
	/* Ensure that the write to ctl register has taken effect. */
	isb();
}

/**
 * Disable host timer and configure the PPI associated with it.
 */
void host_timer_init(void)
{
	host_timer_disable();

#if SECURE_WORLD == 1
	struct interrupt_descriptor int_desc = {
		.interrupt_id = ARM_SEL2_TIMER_PHYS_INT,
		.type = INT_DESC_TYPE_PPI,
		.config = 1U, /* Level-sensitive */
		.sec_state = INT_DESC_SEC_STATE_S,
		.priority = 0x0,
		.valid = true,
		.mpidr_valid = false,
		.enabled = true,
	};

	plat_interrupts_configure_interrupt(int_desc);
#endif
}

/**
 * Save the arch timer state being tracked by host timer.
 */
void host_timer_save_arch_timer(struct timer_state *timer)
{
#if SECURE_WORLD == 1
	timer->cval = read_msr(MSR_CNTHPS_CVAL_EL2);
	timer->ctl = read_msr(MSR_CNTHPS_CTL_EL2);
#else
	timer->cval = read_msr(MSR_CNTHP_CVAL_EL2);
	timer->ctl = read_msr(MSR_CNTHP_CTL_EL2);
#endif
}

/**
 * Configure the host timer to track the arch timer deadline.
 */
void host_timer_track_deadline(struct timer_state *timer)
{
	/*
	 * Clear timer control register before restoring compare value, to avoid
	 * a spurious timer interrupt. This could be a problem if the interrupt
	 * is configured as edge-triggered, as it would then be latched in.
	 */
#if SECURE_WORLD == 1
	write_msr(cnthps_ctl_el2, 0);
	write_msr(cnthps_cval_el2, timer->cval);
	write_msr(cnthps_ctl_el2, timer->ctl);
#else
	write_msr(cnthp_ctl_el2, 0);
	write_msr(cnthp_cval_el2, timer->cval);
	write_msr(cnthp_ctl_el2, timer->ctl);
#endif
	/* Ensure that the write to ctl register has taken effect. */
	isb();
}
