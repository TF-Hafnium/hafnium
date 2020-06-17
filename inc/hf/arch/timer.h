/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "hf/arch/types.h"

/**
 * Sets the bit to mask virtual timer interrupts.
 */
void arch_timer_mask(struct arch_regs *regs);

/**
 * Checks whether the virtual timer is enabled and its interrupt not masked.
 */
bool arch_timer_enabled(struct arch_regs *regs);

/**
 * Returns the number of nanoseconds remaining on the virtual timer as stored in
 * the given `arch_regs`, or 0 if it has already expired. This is undefined if
 * the timer is not enabled.
 */
uint64_t arch_timer_remaining_ns(struct arch_regs *regs);

/**
 * Returns whether the timer is ready to fire: i.e. it is enabled, not masked,
 * and the condition is met.
 */
bool arch_timer_pending(struct arch_regs *regs);

/**
 * Checks whether the virtual timer is enabled and its interrupt not masked, for
 * the currently active vCPU.
 */
bool arch_timer_enabled_current(void);

/**
 * Disable the virtual timer for the currently active vCPU.
 */
void arch_timer_disable_current(void);

/**
 * Returns the number of nanoseconds remaining on the virtual timer of the
 * currently active vCPU, or 0 if it has already expired. This is undefined if
 * the timer is not enabled.
 */
uint64_t arch_timer_remaining_ns_current(void);
