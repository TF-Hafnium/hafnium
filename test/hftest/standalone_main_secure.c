/*
 * Copyright 2020 The Hafnium Authors.
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

alignas(4096) uint8_t kstack[4096];

static struct ffa_boot_info_header* boot_info_header;

struct ffa_boot_info_header* get_boot_info_header(void)
{
	return boot_info_header;
}

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

static noreturn void hftest_wait(void)
{
	for (;;) {
		interrupt_wait();
	}
}

void kmain(struct ffa_boot_info_header* boot_info_blob)
{
	/* Dummy fdt. It is not really used */
	struct fdt fdt;

	/*
	 * Initialize the stage-1 MMU and identity-map the entire address space.
	 */
	if ((VM_TOOLCHAIN == 1) && !hftest_mm_init()) {
		HFTEST_LOG("Memory initialization failed.");
		goto out;
	}

	boot_info_header = boot_info_blob;

	/*
	 * Install the exception handler with no IRQ callback for now, so that
	 * exceptions are logged.
	 */
	exception_setup(NULL, NULL);

	hftest_use_list(hftest_begin, hftest_end - hftest_begin);

	hftest_command(&fdt);

out:
	hftest_ctrl_finish();
	hftest_wait();
}
