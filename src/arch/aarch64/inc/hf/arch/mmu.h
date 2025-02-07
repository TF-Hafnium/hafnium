/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/** AArch64-specific mapping modes */

/** Mapping mode defining MMU Stage-1 block/page non-secure bit */
#define MM_MODE_NS (1U << 7)

/** Page mapping mode for tagged normal memory. */
#define MM_MODE_T (1U << 10)

#define tlbi(op)                               \
	do {                                   \
		__asm__ volatile("tlbi " #op); \
	} while (0)
#define tlbi_reg(op, reg)                                              \
	do {                                                           \
		__asm__ __volatile__("tlbi " #op ", %0" : : "r"(reg)); \
	} while (0)
