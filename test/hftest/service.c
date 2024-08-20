/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/interrupts.h"

#include "test/hftest.h"
#include "test/hftest_impl.h"

alignas(4096) uint8_t kstack[4096];

extern void abort(void);

void run_service_set_up(struct hftest_context *ctx, struct fdt *fdt)
{
	hftest_service_set_up(ctx, fdt);
}

noreturn void kmain(const void *fdt_ptr)
{
	/*
	 * Initialize the stage-1 MMU and identity-map the entire address space.
	 */
	if (!hftest_mm_init()) {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT "Memory initialization failed");
		abort();
	}

	/* Setup basic exception handling. */
	exception_setup(NULL, NULL);

	hftest_service_main(fdt_ptr);
}
