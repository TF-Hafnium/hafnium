/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/std.h"
#include "hf/arch/vm/registers.h"

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "test/hftest.h"

TEST_SERVICE(fp_fill)
{
	const double value = 0.75;
	fill_fp_registers(value);
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

	ASSERT_TRUE(check_fp_register(value));
	ffa_yield();
}

TEST_SERVICE(fp_fpcr)
{
	uintreg_t value = 3 << 22; /* Set RMode to RZ */
	write_msr(fpcr, value);
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

	ASSERT_EQ(read_msr(fpcr), value);
	ffa_yield();
}
