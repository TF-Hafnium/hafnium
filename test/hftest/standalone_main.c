/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/interrupts.h"

#include "hf/mm.h"

#include "hftest_common.h"
#include "test/hftest.h"

alignas(4096) uint8_t kstack[2 * 4096];

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

void kmain(const void *fdt_ptr)
{
	struct fdt fdt;
	size_t fdt_len;

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

	hftest_command(&fdt);

out:
	hftest_ctrl_finish();
	hftest_ctrl_reboot();
}
