/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "smc.h"

#include <stdint.h>

#include "vmapi/hf/spci.h"

static struct spci_value smc_internal(uint32_t func, uint64_t arg0,
				      uint64_t arg1, uint64_t arg2,
				      uint64_t arg3, uint64_t arg4,
				      uint64_t arg5, uint32_t caller_id)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = arg3;
	register uint64_t r5 __asm__("x5") = arg4;
	register uint64_t r6 __asm__("x6") = arg5;
	register uint64_t r7 __asm__("x7") = caller_id;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7));

	return (struct spci_value){.func = r0,
				   .arg1 = r1,
				   .arg2 = r2,
				   .arg3 = r3,
				   .arg4 = r4,
				   .arg5 = r5,
				   .arg6 = r6,
				   .arg7 = r7};
}

struct spci_value smc32(uint32_t func, uint32_t arg0, uint32_t arg1,
			uint32_t arg2, uint32_t arg3, uint32_t arg4,
			uint32_t arg5, uint32_t caller_id)
{
	return smc_internal(func | SMCCC_32_BIT, arg0, arg1, arg2, arg3, arg4,
			    arg5, caller_id);
}

struct spci_value smc64(uint32_t func, uint64_t arg0, uint64_t arg1,
			uint64_t arg2, uint64_t arg3, uint64_t arg4,
			uint64_t arg5, uint32_t caller_id)
{
	return smc_internal(func | SMCCC_64_BIT, arg0, arg1, arg2, arg3, arg4,
			    arg5, caller_id);
}

struct spci_value smc_forward(uint32_t func, uint64_t arg0, uint64_t arg1,
			      uint64_t arg2, uint64_t arg3, uint64_t arg4,
			      uint64_t arg5, uint32_t caller_id)
{
	return smc_internal(func, arg0, arg1, arg2, arg3, arg4, arg5,
			    caller_id);
}
