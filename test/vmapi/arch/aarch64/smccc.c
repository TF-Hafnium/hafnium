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
