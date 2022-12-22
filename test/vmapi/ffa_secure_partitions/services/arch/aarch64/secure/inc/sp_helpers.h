/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

/* Secure watchdog timer interrupt id. */
#define IRQ_TWDOG_INTID 56

uint64_t sp_sleep_active_wait(uint32_t ms);
void sp_enable_irq(void);
