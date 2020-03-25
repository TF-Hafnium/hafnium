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

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/interrupts.h"

#include "hf/mm.h"

#include "hftest_common.h"
#include "test/hftest.h"

alignas(4096) uint8_t kstack[4096];

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

void kmain(const void *fdt_ptr)
{
	struct fdt fdt;
	size_t fdt_len;
	struct memiter command_line;
	struct memiter command;

	/*
	 * Initialize the stage-1 MMU and identity-map the entire address space.
	 */
	if ((VM_TOOLCHAIN == 1) && !hftest_mm_init()) {
		HFTEST_LOG("Memory initialization failed.");
		goto out;
	}

	/*
	 * Install the exception handler with no IRQ callback for now, so that
	 * exceptions are logged.
	 */
	exception_setup(NULL, NULL);

	hftest_use_list(hftest_begin, hftest_end - hftest_begin);

	if (!fdt_size_from_header(fdt_ptr, &fdt_len) ||
	    !fdt_init_from_ptr(&fdt, fdt_ptr, fdt_len)) {
		HFTEST_LOG("Unable to init FDT.");
		goto out;
	}

	if (!hftest_ctrl_start(&fdt, &command_line)) {
		HFTEST_LOG("Unable to read the command line.");
		goto out;
	}

	if (!memiter_parse_str(&command_line, &command)) {
		HFTEST_LOG("Unable to parse command.");
		goto out;
	}

	if (memiter_iseq(&command, "exit")) {
		hftest_device_exit_test_environment();
		goto out;
	}

	if (memiter_iseq(&command, "json")) {
		hftest_json();
		goto out;
	}

	if (memiter_iseq(&command, "run")) {
		struct memiter suite_name;
		struct memiter test_name;

		if (!memiter_parse_str(&command_line, &suite_name)) {
			HFTEST_LOG("Unable to parse test suite.");
			goto out;
		}

		if (!memiter_parse_str(&command_line, &test_name)) {
			HFTEST_LOG("Unable to parse test.");
			goto out;
		}
		hftest_run(suite_name, test_name, &fdt);
		goto out;
	}

	hftest_help();

out:
	hftest_ctrl_finish();
}
