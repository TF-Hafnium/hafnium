/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdbool.h>
#include <stdint.h>

#if defined(__ASSEMBLY__)
#define STATIC_ASSERT(expr, msg) 0
#else
#define STATIC_ASSERT(expr, msg)          \
	__extension__({                   \
		static_assert(expr, msg); \
		0;                        \
	})
#endif

/**
 * NOTE: The below macroos use the notation `[hi:lo]` to mean the bits
 * from `lo` up-to and including `hi`. This matches the notation used in the
 * FF-A specification.
 * Examples:
 * - bits `[4:0]` of `0xAF` are `1111`,
 * - bits `[7:4]` of `0xAF` are `1010`,
 * - bits `[31:0]`  means the lower half of a 64-bit integer
 * - bits `[63:32]` means the upper half of a 64-bit integer
 * - bits `[63:0]`  means the whole 64-bit integer
 */

/**
 * Isolate the `n`th bit of `value`.
 */
#define GET_BIT(value, n)                             \
	(STATIC_ASSERT((n) < 64, "n out of bounds") + \
	 ((value) & (UINT64_C(1) << (n))))

/**
 * Return true if the `n`th bit of `value` is 1.
 */
#define IS_BIT_SET(value, n) (GET_BIT(value, n) != 0)

/**
 * Return true if the `n`th bit of `value` is 0.
 */
#define IS_BIT_UNSET(value, n) (GET_BIT(value, n) == 0)

/**
 * Return a mask suitable for isolating bits `[hi:lo]` of a 64-bit
 * integer.
 */
#define GET_BITS_MASK(hi, lo)                              \
	(STATIC_ASSERT((hi) < 64, "hi out of bounds") +    \
	 STATIC_ASSERT((hi) >= (lo), "hi must be >= lo") + \
	 (((~UINT64_C(0)) - (UINT64_C(1) << (lo)) + 1) &   \
	  (~UINT64_C(0) >> (64 - 1 - (hi)))))

/**
 * Isolate bits `[hi:lo]` of `value`.
 */
#define GET_BITS(value, hi, lo) ((value) & GET_BITS_MASK(hi, lo))

/**
 * Return true if any bits `[lo:hi]` of `value` are 1.
 */
#define ANY_BITS_SET(value, hi, lo) (GET_BITS(value, hi, lo) != 0)

/**
 * Return true if all bits `[lo:hi]` of `value` are 1.
 */
#define ALL_BITS_SET(value, hi, lo) \
	(GET_BITS(value, hi, lo) == GET_BITS_MASK(hi, lo))

/**
 * Return true if any bits `[lo:hi]` of `value` are 0.
 */
#define ANY_BITS_UNSET(value, hi, lo) (!ALL_BITS_SET(value, hi, lo))

/**
 * Return true if all bits `[lo:hi]` of `value` are 0.
 */
#define ALL_BITS_UNSET(value, hi, lo) (!ANY_BITS_SET(value, hi, lo))
