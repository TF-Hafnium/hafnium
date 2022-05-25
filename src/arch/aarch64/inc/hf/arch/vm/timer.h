/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "../msr.h"
#include "../sysregs.h"

#define NANOS_PER_UNIT 1000000000

/* Generic timer control interface. */
#define CNTx_CTL_ENABLE_MASK (UINT32_C(1) << 0)
#define CNTx_CTL_IMASK_MASK (UINT32_C(1) << 1)
#define CNTx_CTL_ISTS_MASK (UINT32_C(1) << 2)

static inline void timer_set(uint32_t ticks)
{
	has_vhe_support() ? write_msr(MSR_CNTV_TVAL_EL02, ticks)
			  : write_msr(cntv_tval_el0, ticks);
}

static inline void timer_start(void)
{
	has_vhe_support() ? write_msr(MSR_CNTV_CTL_EL02, 0x00000001)
			  : write_msr(cntv_ctl_el0, 0x00000001);
}

/**
 * Converts a number of nanoseconds to the equivalent number of timer ticks.
 */
static inline uint64_t ns_to_ticks(uint64_t ns)
{
	return ns * read_msr(cntfrq_el0) / NANOS_PER_UNIT;
}
