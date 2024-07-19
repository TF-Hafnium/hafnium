/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "ap_refclk_generic_timer.h"

#include "system_timer.h"

void program_ap_refclk_timer(uint32_t time_out_ms)
{
	program_systimer((void *)AP_REFCLK_GENERIC_TIMER_BASE, time_out_ms);
}

void cancel_ap_refclk_timer(void)
{
	cancel_systimer((void *)AP_REFCLK_GENERIC_TIMER_BASE);
}

void init_ap_refclk_timer(void)
{
	init_systimer((void *)AP_REFCLK_GENERIC_TIMER_BASE);
}
