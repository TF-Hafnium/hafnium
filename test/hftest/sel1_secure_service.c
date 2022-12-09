/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/ffa.h"
#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/abort.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static struct ffa_boot_info_header* boot_info_header;

struct ffa_boot_info_header* get_boot_info_header(void)
{
	return boot_info_header;
}

alignas(4096) uint8_t kstack[MAX_CPUS][4096];

void test_main_sp(bool);

noreturn void kmain(struct ffa_boot_info_header* boot_info_blob)
{
	extern void secondary_ep_entry(void);
	struct ffa_value res;

	/*
	 * Initialize the stage-1 MMU and identity-map the entire address space.
	 */
	if (!hftest_mm_init()) {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT "Memory initialization failed");
		abort();
	}

	/* Register entry point for secondary vCPUs. */
	res = ffa_secondary_ep_register((uintptr_t)secondary_ep_entry);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	boot_info_header = boot_info_blob;

	test_main_sp(true);

	/* Do not expect to get to this point, so abort. */
	abort();
}
