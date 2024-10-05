/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sp805.h"

#include "hf/mmio.h"

#include "test/hftest.h"

static inline void sp805_write_wdog_load(void *base, uint32_t value)
{
	mmio_write32_offset(base, SP805_WDOG_LOAD_OFF, value);
}

static inline void sp805_write_wdog_ctrl(void *base, uint32_t value)
{
	/* Not setting reserved bits. */
	ASSERT_FALSE((value & ~SP805_WDOG_CTRL_MASK));
	mmio_write32_offset(base, SP805_WDOG_CTRL_OFF, value);
}

static inline void sp805_write_wdog_int_clr(void *base, uint32_t value)
{
	mmio_write32_offset(base, SP805_WDOG_INT_CLR_OFF, value);
}

static inline void sp805_write_wdog_lock(void *base, uint32_t value)
{
	mmio_write32_offset(base, SP805_WDOG_LOCK_OFF, value);
}

void sp805_start(void *base, uint32_t wdog_cycles)
{
	/* Unlock to access the watchdog registers. */
	sp805_write_wdog_lock(base, SP805_WDOG_UNLOCK_ACCESS);

	/* Write the number of cycles needed. */
	sp805_write_wdog_load(base, wdog_cycles);

	/* Enable reset interrupt and watchdog interrupt on expiry. */
	sp805_write_wdog_ctrl(base,
			      SP805_WDOG_CTRL_RESEN | SP805_WDOG_CTRL_INTEN);

	/* Lock registers so that they can't be accidently overwritten. */
	sp805_write_wdog_lock(base, 0x0);
}

void sp805_stop(void *base)
{
	/* Unlock to access the watchdog registers. */
	sp805_write_wdog_lock(base, SP805_WDOG_UNLOCK_ACCESS);

	/* Clearing INTEN bit stops the counter. */
	sp805_write_wdog_ctrl(base, 0x00);

	/* Lock registers so that they can't be accidently overwritten. */
	sp805_write_wdog_lock(base, 0x0);
}

void sp805_refresh(void *base)
{
	/* Unlock to access the watchdog registers. */
	sp805_write_wdog_lock(base, SP805_WDOG_UNLOCK_ACCESS);

	/*
	 * Write of any value to WdogIntClr clears interrupt and reloads
	 * the counter from the value in WdogLoad Register.
	 */
	sp805_write_wdog_int_clr(base, 1);

	/* Lock registers so that they can't be accidently overwritten. */
	sp805_write_wdog_lock(base, 0x0);
}
