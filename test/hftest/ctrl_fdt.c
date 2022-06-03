/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/check.h"

#include "test/hftest.h"

bool hftest_ctrl_start(const struct fdt *fdt, struct memiter *cmd)
{
	struct fdt_node n;
	struct memiter bootargs;

	if (!fdt_find_node(fdt, "/chosen", &n)) {
		HFTEST_LOG("Could not find '/chosen' node.");
		return false;
	}

	if (!fdt_read_property(&n, "bootargs", &bootargs)) {
		HFTEST_LOG("Unable to read bootargs.");
		return false;
	}

	/* Remove null terminator. */
	CHECK(memiter_restrict(&bootargs, 1));
	*cmd = bootargs;
	return true;
}

void hftest_ctrl_finish(void)
{
	/* Nothing to do. */
}

void hftest_ctrl_reboot(void)
{
	/* Nothing to do. */
}
