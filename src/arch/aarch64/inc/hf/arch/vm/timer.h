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
