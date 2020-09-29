/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "../msr.h"

static inline void timer_set(uint32_t ticks)
{
	write_msr(CNTV_TVAL_EL0, ticks);
}

static inline void timer_start(void)
{
	write_msr(CNTV_CTL_EL0, 0x00000001);
}
