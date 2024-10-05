/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#define ARM_SP805_WDOG_CLK_HZ 24000000
#define SP805_WDOG_BASE 0x1C0F0000

/* Normal world watchdog timer interrupt id. */
#define IRQ_WDOG_INTID 32

/* Public APIs for normal world watchdog module. */
void wdog_start(unsigned int wdog_cycles);
void wdog_stop(void);
void wdog_refresh(void);
