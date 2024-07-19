/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "system_timer.h"

#include "hf/mmio.h"

static uint32_t read_cntfrq_systimer(void *systimer_base)
{
	return mmio_read32_offset(systimer_base, CNTFRQ_OFF);
}

void program_systimer(void *systimer_base, uint32_t time_out_ms)
{
	uint32_t cntp_ctl;
	uint64_t count_val;
	uint32_t freq;

	count_val = mmio_read64_offset(systimer_base, CNTPCT_LO_OFF);
	freq = read_cntfrq_systimer(systimer_base);
	count_val += (freq * time_out_ms) / 1000;
	mmio_write64_offset(systimer_base, CNTP_CVAL_LO_OFF, count_val);

	/* Enable the timer and unmask the interrupt. */
	cntp_ctl = mmio_read32_offset(systimer_base, CNTP_CTL_OFF);
	cntp_ctl |= (1U << CNTP_CTL_ENABLE_SHIFT);
	cntp_ctl &= ~(1U << CNTP_CTL_IMASK_SHIFT);
	mmio_write32_offset(systimer_base, CNTP_CTL_OFF, cntp_ctl);
}

static void disable_systimer(void *systimer_base)
{
	uint32_t val;

	/* Disable the timer and mask the interrupt */
	val = 0;
	val |= (1U << CNTP_CTL_IMASK_SHIFT);
	mmio_write32_offset(systimer_base, CNTP_CTL_OFF, val);
}

void cancel_systimer(void *systimer_base)
{
	disable_systimer(systimer_base);
}

void init_systimer(void *systimer_base)
{
	/* Disable the timer as the reset value is unknown. */
	disable_systimer(systimer_base);

	/* Initialise CVAL to zero */
	mmio_write64_offset(systimer_base, CNTP_CVAL_LO_OFF, 0);
}
