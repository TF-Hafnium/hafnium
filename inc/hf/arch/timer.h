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
 * Checks whether the arch timer is enabled and its interrupt not masked.
 */
bool arch_timer_enabled(struct arch_regs *regs);

/**
 * Returns the number of nanoseconds remaining on the arch timer as stored in
 * the given `arch_regs`, or 0 if it has already expired. This is undefined if
 * the timer is not enabled.
 */
uint64_t arch_timer_remaining_ns(struct arch_regs *regs);

/**
 * Returns whether the timer is ready to fire: i.e. it is enabled, not masked,
 * and the condition is met.
 */
bool arch_timer_expired(struct arch_regs *regs);
