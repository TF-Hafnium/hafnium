/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "smc.h"

#include <stdint.h>

#include "hf/assert.h"

#include "vmapi/hf/ffa.h"

static struct ffa_value smc_internal_ext(uint32_t func, uint64_t arg0,
					 uint64_t arg1, uint64_t arg2,
					 uint64_t arg3, uint64_t arg4,
					 uint64_t arg5, uint64_t arg6)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = arg3;
	register uint64_t r5 __asm__("x5") = arg4;
	register uint64_t r6 __asm__("x6") = arg5;
	register uint64_t r7 __asm__("x7") = arg6;
	register uint64_t r8 __asm__("x8") = 0;
	register uint64_t r9 __asm__("x9") = 0;
	register uint64_t r10 __asm__("x10") = 0;
	register uint64_t r11 __asm__("x11") = 0;
	register uint64_t r12 __asm__("x12") = 0;
	register uint64_t r13 __asm__("x13") = 0;
	register uint64_t r14 __asm__("x14") = 0;
	register uint64_t r15 __asm__("x15") = 0;
	register uint64_t r16 __asm__("x16") = 0;
	register uint64_t r17 __asm__("x17") = 0;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7), "=r"(r8), "=r"(r9), "=r"(r10), "=r"(r11),
		"=r"(r12), "=r"(r13), "=r"(r14), "=r"(r15), "=r"(r16),
		"=r"(r17));

	return (struct ffa_value){.func = r0,
				  .arg1 = r1,
				  .arg2 = r2,
				  .arg3 = r3,
				  .arg4 = r4,
				  .arg5 = r5,
				  .arg6 = r6,
				  .arg7 = r7,
				  .extended_val.valid = 1,
				  .extended_val.arg8 = r8,
				  .extended_val.arg9 = r9,
				  .extended_val.arg10 = r10,
				  .extended_val.arg11 = r11,
				  .extended_val.arg12 = r12,
				  .extended_val.arg13 = r13,
				  .extended_val.arg14 = r14,
				  .extended_val.arg15 = r15,
				  .extended_val.arg16 = r16,
				  .extended_val.arg17 = r17};
}

static struct ffa_value smc_internal(uint32_t func, uint64_t arg0,
				     uint64_t arg1, uint64_t arg2,
				     uint64_t arg3, uint64_t arg4,
				     uint64_t arg5, uint64_t arg6)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = arg3;
	register uint64_t r5 __asm__("x5") = arg4;
	register uint64_t r6 __asm__("x6") = arg5;
	register uint64_t r7 __asm__("x7") = arg6;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7));

	return (struct ffa_value){.func = r0,
				  .arg1 = r1,
				  .arg2 = r2,
				  .arg3 = r3,
				  .arg4 = r4,
				  .arg5 = r5,
				  .arg6 = r6,
				  .arg7 = r7};
}

/** Make an SMC call following the 32-bit SMC calling convention. */
struct ffa_value smc32(uint32_t func, uint32_t arg0, uint32_t arg1,
		       uint32_t arg2, uint32_t arg3, uint32_t arg4,
		       uint32_t arg5, uint32_t caller_id)
{
	return smc_internal(func | SMCCC_32_BIT, arg0, arg1, arg2, arg3, arg4,
			    arg5, caller_id);
}

/** Make an SMC call following the 64-bit SMC calling convention. */
struct ffa_value smc64(uint32_t func, uint64_t arg0, uint64_t arg1,
		       uint64_t arg2, uint64_t arg3, uint64_t arg4,
		       uint64_t arg5, uint32_t caller_id)
{
	return smc_internal(func | SMCCC_64_BIT, arg0, arg1, arg2, arg3, arg4,
			    arg5, caller_id);
}

/** Forward a raw SMC on to EL3. */
struct ffa_value smc_forward(uint32_t func, uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3, uint64_t arg4,
			     uint64_t arg5, uint32_t caller_id)
{
	return smc_internal(func, arg0, arg1, arg2, arg3, arg4, arg5,
			    caller_id);
}

/**
 * Make an FF-A call up to EL3. Assumes the function ID is already masked
 * appropriately for the 32-bit or 64-bit SMCCC.
 */
struct ffa_value smc_ffa_call(struct ffa_value args)
{
	return smc_internal(args.func, args.arg1, args.arg2, args.arg3,
			    args.arg4, args.arg5, args.arg6, args.arg7);
}

struct ffa_value smc_ffa_call_ext(struct ffa_value args)
{
	/* Only one FF-A v1.2 SMC function allowed to use this helper. */
	assert(args.func == FFA_PARTITION_INFO_GET_REGS_64);

	return smc_internal_ext(args.func, args.arg1, args.arg2, args.arg3,
				args.arg4, args.arg5, args.arg6, args.arg7);
}
