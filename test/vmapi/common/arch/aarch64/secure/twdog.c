/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "twdog.h"

#include "sp805.h"

void twdog_start(uint32_t wdog_cycles)
{
	sp805_start((void *)SP805_TWDOG_BASE, wdog_cycles);
}

void twdog_stop(void)
{
	sp805_stop((void *)SP805_TWDOG_BASE);
}

void twdog_refresh(void)
{
	sp805_refresh((void *)SP805_TWDOG_BASE);
}
