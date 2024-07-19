/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "stdint.h"

/*
 * Register offsets in the CNTBaseN Frame of the system level implementation
 * of the Generic Timer.
 */
/* Physical Count register. */
#define CNTPCT_LO_OFF 0x0
/* Counter Frequency register. */
#define CNTFRQ_OFF 0x10
/* Physical Timer CompareValue register. */
#define CNTP_CVAL_LO_OFF 0x20
/* Physical Timer Control register. */
#define CNTP_CTL_OFF 0x2c

/* Physical timer control register bit fields shifts and masks */
#define CNTP_CTL_ENABLE_SHIFT 0x0
#define CNTP_CTL_IMASK_SHIFT 0x1
#define CNTP_CTL_ISTATUS_SHIFT 0x2

/*
 * Program systimer to fire an interrupt after time_out_ms
 */
void program_systimer(void *systimer_base, uint32_t time_out_ms);

/*
 * Cancel the currently programmed systimer interrupt
 */
void cancel_systimer(void *systimer_base);

/*
 * Initializes the systimer so that it can be used for programming timer
 * interrupt.
 */
void init_systimer(void *systimer_base);
