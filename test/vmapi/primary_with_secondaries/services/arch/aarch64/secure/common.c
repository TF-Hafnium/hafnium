/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"
#include "hf/arch/vm/timer.h"

static inline uint64_t physicalcounter_read(void)
{
	isb();
	return read_msr(cntpct_el0);
}

uint64_t sp_wait(uint32_t ms)
{
	uint64_t timer_freq = read_msr(cntfrq_el0);

	uint64_t time1 = physicalcounter_read();
	volatile uint64_t time2 = time1;

	while ((time2 - time1) < ((ms * timer_freq) / 1000U)) {
		time2 = physicalcounter_read();
	}

	return ((time2 - time1) * 1000) / timer_freq;
}
