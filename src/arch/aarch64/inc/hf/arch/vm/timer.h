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

static inline uint64_t timer_ms_to_ticks(uint64_t ms)
{
	return ms * read_msr(cntfrq_el0) / 1000;
}

static inline void timer_set(uint32_t ms)
{
	write_msr(cntp_tval_el0, timer_ms_to_ticks(ms));
}

static inline void timer_start(void)
{
	write_msr(cntp_ctl_el0, 0x1);
}

static inline void timer_disable(void)
{
	write_msr(cntp_ctl_el0, 0x0);
}
