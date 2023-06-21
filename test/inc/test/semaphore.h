/*
 * Copyright 2024 The Hafnium Authors.
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

/* TODO: For now, semaphore is a wrapper to spinlock.
 * In the future, introduce counter within semaphore struct.
 */
struct semaphore {
	struct spinlock lock;
};

static inline void semaphore_init(struct semaphore *a)
{
	sl_init(&a->lock);
	sl_lock(&a->lock);
}

static inline void semaphore_wait(struct semaphore *a)
{
	sl_lock(&a->lock);
}

static inline void semaphore_signal(struct semaphore *a)
{
	sl_unlock(&a->lock);
}
