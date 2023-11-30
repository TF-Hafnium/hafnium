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

static struct ffa_value smc_internal_ext(
	uint32_t func, uint64_t arg0, uint64_t arg1, uint64_t arg2,
	uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
	uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10,
	uint64_t arg11, uint64_t arg12, uint64_t arg13, uint64_t arg14,
	uint64_t arg15, uint64_t arg16)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = arg3;
	register uint64_t r5 __asm__("x5") = arg4;
	register uint64_t r6 __asm__("x6") = arg5;
	register uint64_t r7 __asm__("x7") = arg6;
	register uint64_t r8 __asm__("x8") = arg7;
	register uint64_t r9 __asm__("x9") = arg8;
	register uint64_t r10 __asm__("x10") = arg9;
	register uint64_t r11 __asm__("x11") = arg10;
	register uint64_t r12 __asm__("x12") = arg11;
	register uint64_t r13 __asm__("x13") = arg12;
	register uint64_t r14 __asm__("x14") = arg13;
	register uint64_t r15 __asm__("x15") = arg14;
	register uint64_t r16 __asm__("x16") = arg15;
	register uint64_t r17 __asm__("x17") = arg16;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		"+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(r16),
		"+r"(r17));

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
	/* Only these FF-A v1.2 SMC functions allowed to use this helper. */
	assert(args.func == FFA_PARTITION_INFO_GET_REGS_64 ||
	       args.func == FFA_RUN_32 ||
	       args.func == FFA_MSG_SEND_DIRECT_REQ2_64 ||
	       args.func == FFA_MSG_SEND_DIRECT_RESP2_64);

	return smc_internal_ext(
		args.func, args.arg1, args.arg2, args.arg3, args.arg4,
		args.arg5, args.arg6, args.arg7, args.extended_val.arg8,
		args.extended_val.arg9, args.extended_val.arg10,
		args.extended_val.arg11, args.extended_val.arg12,
		args.extended_val.arg13, args.extended_val.arg14,
		args.extended_val.arg15, args.extended_val.arg16,
		args.extended_val.arg17);
}
