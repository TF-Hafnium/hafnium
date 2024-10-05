/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/std.h"

/* SP805 register offset. */
#define SP805_WDOG_LOAD_OFF 0x000
#define SP805_WDOG_CTRL_OFF 0x008
#define SP805_WDOG_INT_CLR_OFF 0x00c
#define SP805_WDOG_LOCK_OFF 0xc00

/*
 * Magic word to unlock access to all other watchdog registers, writing any
 * other value locks them.
 */
#define SP805_WDOG_UNLOCK_ACCESS 0x1ACCE551

/* The register field definitions. */
#define SP805_WDOG_CTRL_MASK 0x03
#define SP805_WDOG_CTRL_RESEN (1 << 1)
#define SP805_WDOG_CTRL_INTEN (1 << 0)

void sp805_start(void *base, uint32_t wdog_cycles);

void sp805_stop(void *base);

void sp805_refresh(void *base);
