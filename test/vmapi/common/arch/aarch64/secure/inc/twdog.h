/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#define ARM_SP805_TWDG_CLK_HZ 32768
#define SP805_TWDOG_BASE 0x2A490000

/* Secure watchdog timer interrupt id. */
#define IRQ_TWDOG_INTID 56

/* Public APIs for trusted watchdog module. */
void twdog_start(unsigned int wdog_cycles);
void twdog_stop(void);
void twdog_refresh(void);
