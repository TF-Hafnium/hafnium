/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "stdint.h"

/* AP_REFCLK CNTBase1 Generic timer definitions */
#define AP_REFCLK_GENERIC_TIMER_BASE 0x2A830000
#define AP_REFCLK_GENERIC_TIMER_SIZE 0x1000
#define IRQ_AP_REFCLK_BASE1_INTID 58

/* Program systimer to fire an interrupt after time_out_ms. */
void program_ap_refclk_timer(uint32_t time_out_ms);

/* Cancel the currently programmed systimer interrupt. */
void cancel_ap_refclk_timer(void);

/*
 * Initialises the systimer so that it can be used for programming timer
 * interrupt.
 */
void init_ap_refclk_timer(void);
