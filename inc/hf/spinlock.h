/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/*
 * Includes the arch-specific definition of 'struct spinlock' and
 * implementations of:
 *  - SPINLOCK_INIT
 *  - sl_lock()
 *  - sl_unlock()
 */
#include "hf/arch/spinlock.h"

/**
 * Locks both locks, enforcing the lowest address first ordering for locks of
 * the same kind.
 */
static inline void sl_lock_both(struct spinlock *a, struct spinlock *b)
{
	if (a < b) {
		sl_lock(a);
		sl_lock(b);
	} else {
		sl_lock(b);
		sl_lock(a);
	}
}
