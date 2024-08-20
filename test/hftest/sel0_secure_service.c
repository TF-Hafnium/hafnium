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

alignas(4096) uint8_t kstack[4096];

static struct ffa_boot_info_header* boot_info_header;

struct ffa_boot_info_header* get_boot_info_header(void)
{
	return boot_info_header;
}

void test_main_sp(bool);

void run_service_set_up(struct hftest_context* ctx, struct fdt* fdt)
{
	hftest_service_set_up(ctx, fdt);
}

noreturn void kmain(struct ffa_boot_info_header* boot_info_blob)
{
	boot_info_header = boot_info_blob;

	test_main_sp(true);

	/* Do not expect to get to this point, so abort. */
	abort();
}
