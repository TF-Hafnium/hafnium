/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "test/hftest.h"

alignas(4096) uint8_t kstack[4096];

void run_service_set_up(struct hftest_context *ctx, struct fdt *fdt)
{
	hftest_service_set_up(ctx, fdt);
}

noreturn void kmain(const void *fdt_ptr)
{
	hftest_service_main(fdt_ptr);
}
