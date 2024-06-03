/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "smc.h"
#include "test/hftest.h"

TEST(smc_whitelist, not_whitelisted_unknown)
{
	const uint32_t non_whitelisted_ta_call = 0x3000f00d;
	struct ffa_value smc_res = smc_forward(
		non_whitelisted_ta_call, 0x1111111111111111, 0x2222222222222222,
		0x3333333333333333, 0x4444444444444444, 0x5555555555555555,
		0x6666666666666666, 0x77777777);

	EXPECT_EQ((int64_t)smc_res.func, SMCCC_ERROR_UNKNOWN);
	EXPECT_EQ(smc_res.arg1, UINT64_C(0x1111111111111111));
	EXPECT_EQ(smc_res.arg2, UINT64_C(0x2222222222222222));
	EXPECT_EQ(smc_res.arg3, UINT64_C(0x3333333333333333));
	EXPECT_EQ(smc_res.arg4, UINT64_C(0x4444444444444444));
	EXPECT_EQ(smc_res.arg5, UINT64_C(0x5555555555555555));
	EXPECT_EQ(smc_res.arg6, UINT64_C(0x6666666666666666));
	EXPECT_EQ(smc_res.arg7, UINT64_C(0x77777777));
}
