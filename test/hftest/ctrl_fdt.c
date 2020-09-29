/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "test/hftest.h"

bool hftest_ctrl_start(const struct fdt_header *fdt, struct memiter *cmd)
{
	struct fdt_node n;
	const char *bootargs;
	uint32_t bootargs_size;

	if (!fdt_root_node(&n, fdt)) {
		HFTEST_LOG("FDT failed validation.");
		return false;
	}

	if (!fdt_find_child(&n, "")) {
		HFTEST_LOG("Unable to find root node in FDT.");
		return false;
	}

	if (!fdt_find_child(&n, "chosen")) {
		HFTEST_LOG("Unable to find 'chosen' node in FDT.");
		return false;
	}

	if (!fdt_read_property(&n, "bootargs", &bootargs, &bootargs_size)) {
		HFTEST_LOG("Unable to read bootargs.");
		return false;
	}

	/* Remove null terminator. */
	memiter_init(cmd, bootargs, bootargs_size - 1);
	return true;
}

void hftest_ctrl_finish(void)
{
	/* Nothing to do. */
}
