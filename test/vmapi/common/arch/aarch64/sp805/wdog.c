/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "wdog.h"

#include "sp805.h"

void wdog_start(uint32_t wdog_cycles)
{
	sp805_start((void *)SP805_WDOG_BASE, wdog_cycles);
}

void wdog_stop(void)
{
	sp805_stop((void *)SP805_WDOG_BASE);
}

void wdog_refresh(void)
{
	sp805_refresh((void *)SP805_WDOG_BASE);
}
