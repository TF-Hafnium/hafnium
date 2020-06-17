/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/** AArch64-specific API */

/**
 * Ensures explicit memory accesses before this point are completed before any
 * later memory accesses are performed. The instruction argument specifies:
 *   - the shareability domain over which the instruction must operate,
 *   - the accesses for which the instruction operates.
 */
#define dmb(arg)                               \
	do {                                   \
		__asm__ volatile("dmb " #arg); \
	} while (0)

/**
 * Ensures explicit memory access and management instructions have completed
 * before continuing. The instruction argument specifies:
 *   - the shareability domain over which the instruction must operate,
 *   - the accesses for which the instruction operates.
 */
#define dsb(arg)                               \
	do {                                   \
		__asm__ volatile("dsb " #arg); \
	} while (0)

/**
 * Flushes the instruction pipeline so that instructions are fetched from
 * memory.
 */
#define isb()                            \
	do {                             \
		__asm__ volatile("isb"); \
	} while (0)

/** Platform-agnostic API */

/**
 * Ensures all explicit memory accesses before this point are completed before
 * any later memory accesses are performed.
 */
#define memory_ordering_barrier() dmb(sy)

/**
 * Ensures all explicit memory access and management instructions have completed
 * before continuing.
 */
#define data_sync_barrier() dsb(sy)
