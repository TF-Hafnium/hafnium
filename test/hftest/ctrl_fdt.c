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
