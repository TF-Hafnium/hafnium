/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/abort.h"

/**
 * Causes execution to halt and prevent progress of the current and less
 * privileged software components. This should be triggered when a
 * non-recoverable event is identified which leaves the system in an
 * inconsistent state.
 *
 * TODO: Should this also reset the system?
 */
noreturn void abort(void)
{
	/* TODO: Block all CPUs. */
	for (;;) {
		/* Prevent loop being optimized away. */
		__asm__ volatile("nop");
	}
}
