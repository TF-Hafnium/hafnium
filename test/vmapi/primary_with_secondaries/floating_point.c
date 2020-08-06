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
#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(floating_point)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Test that floating point registers are saved and restored by
 * filling them with one value here and a different value in the
 * service.
 */
TEST(floating_point, fp_fill)
{
	const double first = 1.2;
	const double second = -2.3;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	fill_fp_registers(first);
	SERVICE_SELECT(SERVICE_VM1, "fp_fill", mb.send);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(check_fp_register(first), true);

	fill_fp_registers(second);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(check_fp_register(second), true);
}

/**
 * Test that the floating point control register is restored correctly
 * on full context switch when needed by changing it in the service.
 */
TEST(floating_point, fp_fpcr)
{
	uintreg_t value = 0;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	EXPECT_EQ(read_msr(fpcr), value);

	SERVICE_SELECT(SERVICE_VM1, "fp_fpcr", mb.send);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(read_msr(fpcr), value);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(read_msr(fpcr), value);
}
