/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vmapi/hf/call.h"

#include "hftest.h"

TEST(smccc, hf_debug_log_zero_or_unchanged)
{
	register uint64_t r0 __asm__("x0") = HF_DEBUG_LOG;
	register uint64_t r1 __asm__("x1") = '\n';
	register uint64_t r2 __asm__("x2") = UINT64_C(0x2222222222222222);
	register uint64_t r3 __asm__("x3") = UINT64_C(0x3333333333333333);
	register uint64_t r4 __asm__("x4") = UINT64_C(0x4444444444444444);
	register uint64_t r5 __asm__("x5") = UINT64_C(0x5555555555555555);
	register uint64_t r6 __asm__("x6") = UINT64_C(0x6666666666666666);
	register uint64_t r7 __asm__("x7") = UINT64_C(0x7777777777777777);

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7));

	EXPECT_EQ(r0, 0);
	EXPECT_EQ(r1, 0);
	EXPECT_EQ(r2, 0);
	EXPECT_EQ(r3, 0);
	EXPECT_EQ(r4, UINT64_C(0x4444444444444444));
	EXPECT_EQ(r5, UINT64_C(0x5555555555555555));
	EXPECT_EQ(r6, UINT64_C(0x6666666666666666));
	EXPECT_EQ(r7, UINT64_C(0x7777777777777777));
}
