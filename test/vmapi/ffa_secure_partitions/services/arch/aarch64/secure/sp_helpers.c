/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sp_helpers.h"

#include "hf/arch/barriers.h"
#include "hf/arch/irq.h"
#include "hf/arch/vm/timer.h"

static inline uint64_t virtualcounter_read(void)
{
	isb();
	return read_msr(cntvct_el0);
}

uint64_t sp_sleep_active_wait(uint32_t ms)
{
	uint64_t timer_freq = read_msr(cntfrq_el0);

	uint64_t time1 = virtualcounter_read();
	volatile uint64_t time2 = time1;

	while ((time2 - time1) < ((ms * timer_freq) / 1000U)) {
		time2 = virtualcounter_read();
	}

	return ((time2 - time1) * 1000) / timer_freq;
}
