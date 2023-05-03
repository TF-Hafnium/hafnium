/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"

#include "msr.h"

static inline uint64_t syscounter_read(void)
{
	isb();
	return read_msr(cntvct_el0);
}

static inline void waitus(uint64_t us)
{
	uint64_t start_count_val = syscounter_read();
	uint64_t wait_cycles = (us * read_msr(cntfrq_el0)) / 1000000;

	while ((syscounter_read() - start_count_val) < wait_cycles) {
		/* Busy wait... */
	}
}

static inline void waitms(uint64_t ms)
{
	while (ms > 0) {
		waitus(1000);
		ms--;
	}
}
