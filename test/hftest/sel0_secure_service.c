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

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

alignas(4096) uint8_t kstack[4096];

HFTEST_ENABLE();

static struct hftest_context global_context;

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

void test_main_sp(bool);

noreturn void abort(void)
{
	HFTEST_LOG("Service contained failures.");
	/* Cause a fault, as a secondary can't power down the machine. */
	*((volatile uint8_t *)1) = 1;

	/* This should never be reached, but to make the compiler happy... */
	for (;;) {
	}
}

noreturn void kmain(void)
{
	/* Register RX/TX buffers via FFA_RXTX_MAP */
	set_up_mailbox();

	test_main_sp(true);

	/* Do not expect to get to this point, so abort. */
	abort();
}
