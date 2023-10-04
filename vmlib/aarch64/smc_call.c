/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/call.h"
#include "hf/ffa.h"
#include "hf/types.h"

int64_t hf_call(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
	(void)arg0;
	(void)arg1;
	(void)arg2;
	(void)arg3;

	/* hafnium is absent, so return an error. */
	return -1;
}

struct ffa_value ffa_call_ext(struct ffa_value args)
{
	register uint64_t r0 __asm__("x0") = args.func;
	register uint64_t r1 __asm__("x1") = args.arg1;
	register uint64_t r2 __asm__("x2") = args.arg2;
	register uint64_t r3 __asm__("x3") = args.arg3;
	register uint64_t r4 __asm__("x4") = args.arg4;
	register uint64_t r5 __asm__("x5") = args.arg5;
	register uint64_t r6 __asm__("x6") = args.arg6;
	register uint64_t r7 __asm__("x7") = args.arg7;
	register uint64_t r8 __asm__("x8") = args.extended_val.arg8;
	register uint64_t r9 __asm__("x9") = args.extended_val.arg9;
	register uint64_t r10 __asm__("x10") = args.extended_val.arg10;
	register uint64_t r11 __asm__("x11") = args.extended_val.arg11;
	register uint64_t r12 __asm__("x12") = args.extended_val.arg12;
	register uint64_t r13 __asm__("x13") = args.extended_val.arg13;
	register uint64_t r14 __asm__("x14") = args.extended_val.arg14;
	register uint64_t r15 __asm__("x15") = args.extended_val.arg15;
	register uint64_t r16 __asm__("x16") = args.extended_val.arg16;
	register uint64_t r17 __asm__("x17") = args.extended_val.arg17;

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

struct ffa_value ffa_call(struct ffa_value args)
{
	register uint64_t r0 __asm__("x0") = args.func;
	register uint64_t r1 __asm__("x1") = args.arg1;
	register uint64_t r2 __asm__("x2") = args.arg2;
	register uint64_t r3 __asm__("x3") = args.arg3;
	register uint64_t r4 __asm__("x4") = args.arg4;
	register uint64_t r5 __asm__("x5") = args.arg5;
	register uint64_t r6 __asm__("x6") = args.arg6;
	register uint64_t r7 __asm__("x7") = args.arg7;

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
