/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "smc.h"
#include "test/hftest.h"

/**
 * Checks that calling FFA_FEATURES via an SMC works as expected.
 * The ffa_features helper function uses an HVC, but an SMC should also work.
 */
TEST(smccc, ffa_features_smc)
{
	struct ffa_value ret;

	ret = smc32(FFA_FEATURES_32, FFA_VERSION_32, 0, 0, 0, 0, 0, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg1, 0);
	EXPECT_EQ(ret.arg2, 0);
	EXPECT_EQ(ret.arg3, 0);
	EXPECT_EQ(ret.arg4, 0);
	EXPECT_EQ(ret.arg5, 0);
	EXPECT_EQ(ret.arg6, 0);
	EXPECT_EQ(ret.arg7, 0);
}

static struct ffa_value test_ffa_smc(uint32_t func, uint64_t arg0,
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
	register uint64_t r8 __asm__("x8") = 0xa8;
	register uint64_t r9 __asm__("x9") = 0xa9;
	register uint64_t r10 __asm__("x10") = 0xa10;
	register uint64_t r11 __asm__("x11") = 0xa11;
	register uint64_t r12 __asm__("x12") = 0xa12;
	register uint64_t r13 __asm__("x13") = 0xa13;
	register uint64_t r14 __asm__("x14") = 0xa14;
	register uint64_t r15 __asm__("x15") = 0xa15;
	register uint64_t r16 __asm__("x16") = 0xa16;
	register uint64_t r17 __asm__("x17") = 0xa17;
	register uint64_t r18 __asm__("x18") = 0xa18;
	register uint64_t r19 __asm__("x19") = 0xa19;
	register uint64_t r20 __asm__("x20") = 0xa20;
	register uint64_t r21 __asm__("x21") = 0xa21;
	register uint64_t r22 __asm__("x22") = 0xa22;
	register uint64_t r23 __asm__("x23") = 0xa23;
	register uint64_t r24 __asm__("x24") = 0xa24;
	register uint64_t r25 __asm__("x25") = 0xa25;
	register uint64_t r26 __asm__("x26") = 0xa26;
	register uint64_t r27 __asm__("x27") = 0xa27;
	register uint64_t r28 __asm__("x28") = 0xa28;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		"+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(r16),
		"+r"(r17), "+r"(r18), "+r"(r19), "+r"(r20), "+r"(r21),
		"+r"(r22), "+r"(r23), "+r"(r24), "+r"(r25), "+r"(r26),
		"+r"(r27), "+r"(r28));

	EXPECT_EQ(r8, 0xa8);
	EXPECT_EQ(r9, 0xa9);
	EXPECT_EQ(r10, 0xa10);
	EXPECT_EQ(r11, 0xa11);
	EXPECT_EQ(r12, 0xa12);
	EXPECT_EQ(r13, 0xa13);
	EXPECT_EQ(r14, 0xa14);
	EXPECT_EQ(r15, 0xa15);
	EXPECT_EQ(r16, 0xa16);
	EXPECT_EQ(r17, 0xa17);
	EXPECT_EQ(r18, 0xa18);
	EXPECT_EQ(r19, 0xa19);
	EXPECT_EQ(r20, 0xa20);
	EXPECT_EQ(r21, 0xa21);
	EXPECT_EQ(r22, 0xa22);
	EXPECT_EQ(r23, 0xa23);
	EXPECT_EQ(r24, 0xa24);
	EXPECT_EQ(r25, 0xa25);
	EXPECT_EQ(r26, 0xa26);
	EXPECT_EQ(r27, 0xa27);
	EXPECT_EQ(r28, 0xa28);

	return (struct ffa_value){.func = r0,
				  .arg1 = r1,
				  .arg2 = r2,
				  .arg3 = r3,
				  .arg4 = r4,
				  .arg5 = r5,
				  .arg6 = r6,
				  .arg7 = r7};
}

/**
 * An FF-A service call is emitted at the secure physical FF-A instance.
 * The service does not require results in registers beyond x7, hence per
 * SMCCCv1.2 ensure GP registers beyond x7 are preserved by callee.
 */
TEST(smccc, smccc_regs_callee_preserved)
{
	struct ffa_value ret;

	ret = test_ffa_smc(FFA_VERSION_32, 0x10001, 0, 0, 0, 0, 0, 0);
	EXPECT_EQ(ret.func, 0x10002);
	EXPECT_EQ(ret.arg1, 0x0);
	EXPECT_EQ(ret.arg2, 0x0);
	EXPECT_EQ(ret.arg3, 0x0);
	EXPECT_EQ(ret.arg4, 0x0);
	EXPECT_EQ(ret.arg5, 0x0);
	EXPECT_EQ(ret.arg6, 0x0);
	EXPECT_EQ(ret.arg7, 0x0);

	ret = test_ffa_smc(FFA_ID_GET_32, 0, 0, 0, 0, 0, 0, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg1, 0x0);
	EXPECT_EQ(ret.arg2, 1);
	EXPECT_EQ(ret.arg3, 0x0);
	EXPECT_EQ(ret.arg4, 0x0);
	EXPECT_EQ(ret.arg5, 0x0);
	EXPECT_EQ(ret.arg6, 0x0);
	EXPECT_EQ(ret.arg7, 0x0);
}
