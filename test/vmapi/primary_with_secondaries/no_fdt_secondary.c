/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "test/hftest.h"

/**
 * Checks that VM entry is being passed the allocated memory size, rather than a
 * pointer to the FDT.
 */
static void test_memory_size(size_t mem_size)
{
	/*
	 * The memory size this test expects to be allocated for the VM.
	 * This is defined in the manifest (manifest_no_fdt.dts).
	 */
	const size_t expected_mem_size = 0x100000;

	if (mem_size != expected_mem_size) {
		FAIL("Memory size passed to VM entry %zu is not expected size "
		     "of %zu.",
		     mem_size, expected_mem_size);
	}
}

void test_main_secondary(size_t mem_size)
{
	test_memory_size(mem_size);

	/* Yield back to the primary if all tests pass. */
	ffa_yield();
}
