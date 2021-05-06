/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/types.h"

#include "msr.h"

/**
 * plat_prng_get_number
 *
 * Return a 128 bits pseudo random number
 *
 * https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git/tree/plat/arm/common/aarch64/arm_pauth.c?h=v2.4#n17
 * "This is only a toy implementation to generate a seemingly random
 * 128-bit key from sp, x30 and cntpct_el0 values.
 * A production system must re-implement this function to generate
 * keys from a reliable randomness source."
 */
__uint128_t plat_prng_get_number(void)
{
	uint64_t return_addr = (uint64_t)__builtin_return_address(0U);
	uint64_t frame_addr = (uint64_t)__builtin_frame_address(0U);
	uint64_t cntpct = read_msr(cntpct_el0);

	/* Generate 128-bit key */
	uint64_t key_lo = (return_addr << 13) ^ frame_addr ^ cntpct;
	uint64_t key_hi = (frame_addr << 15) ^ return_addr ^ cntpct;

	return ((__uint128_t)key_hi << 64) | (__uint128_t)key_lo;
}
