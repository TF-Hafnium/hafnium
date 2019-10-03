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
#include "smc.h"

TEST(smc_whitelist, not_whitelisted_unknown)
{
	const uint32_t non_whitelisted_ta_call = 0x3000f00d;
	struct smc_result smc_res = smc_forward(
		non_whitelisted_ta_call, 0x1111111111111111, 0x2222222222222222,
		0x3333333333333333, 0x4444444444444444, 0x5555555555555555,
		0x6666666666666666, 0x77777777);

	EXPECT_EQ(smc_res.res0, SMCCC_ERROR_UNKNOWN);
	EXPECT_EQ(smc_res.res1, 0);
	EXPECT_EQ(smc_res.res2, 0);
	EXPECT_EQ(smc_res.res3, 0);
	EXPECT_EQ(smc_res.res4, UINT64_C(0x4444444444444444));
	EXPECT_EQ(smc_res.res5, UINT64_C(0x5555555555555555));
	EXPECT_EQ(smc_res.res6, UINT64_C(0x6666666666666666));
	EXPECT_EQ(smc_res.res7, UINT64_C(0x77777777));
}
