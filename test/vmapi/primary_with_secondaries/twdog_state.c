/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "twdog_state.h"

#include "hf/mm.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/* Pointer tracking the trusted watchdog state. */
static struct hftest_int_state *state_twdog;

void hftest_twdog_state_set(enum int_state to_state)
{
	hftest_int_state_set(state_twdog, to_state);
}

bool hftest_twdog_state_is(enum int_state to_set)
{
	return hftest_int_state_is(state_twdog, to_set);
}

/* Initialize the interrupt status structure at the top of the page. */
static void hftest_twdog_state_init(uintptr_t addr)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	state_twdog = (struct hftest_int_state *)addr;

	hftest_int_state_init(state_twdog, HARDWARE);
}

void hftest_twdog_state_page_setup(void *recv_buf, void *send_buf)
{
	uint64_t addr;

	addr = hftest_int_state_page_setup(recv_buf, send_buf);
	hftest_twdog_state_init(addr);
}

/* Function to share page for the twdog interrupt state structure. */
void hftest_twdog_state_share_page_and_init(uint64_t page,
					    ffa_id_t receivers_ids[],
					    size_t receivers_count,
					    void *send_buf)
{
	share_page_with_endpoints(page, receivers_ids, receivers_count,
				  send_buf);
	hftest_twdog_state_init(page);
}
