/*
 * Copyright 2020 The Hafnium Authors.
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
