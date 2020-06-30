/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/*
 * Run tests where secondary VMs are passed the memory size directly, rather
 * than a pointer to the FDT.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/mm.h"
#include "hf/static_assert.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define SECONDARY_VM1 (HF_VM_ID_OFFSET + 1)

/**
 * Runs the secondary VM and waits for it to yield.
 */
TEST(no_fdt, run_secondary)
{
	struct ffa_value run_res;

	run_res = ffa_run(SECONDARY_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}
