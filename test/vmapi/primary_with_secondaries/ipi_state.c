/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "ipi_state.h"

#include "hf/mm.h"

#include "int_state.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/* Default global state for IPI. */
static struct hftest_int_state ipi = {
	.state = INIT,
	.lock = SPINLOCK_INIT,
	.category = SOFTWARE,
};

/*
 * Global IPI state used the functions below.
 */
static struct hftest_int_state *current_ipi;

bool hftest_ipi_state_is(enum int_state to_check)
{
	return hftest_int_state_is(current_ipi, to_check);
}

void hftest_ipi_state_set(enum int_state to_set)
{
	hftest_int_state_set(current_ipi, to_set);
}

void hftest_ipi_init_state_default(void)
{
	current_ipi = &ipi;
}

static void hftest_ipi_init_state_through_ptr(uintptr_t addr)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	current_ipi = (struct hftest_int_state *)addr;

	hftest_int_state_init(current_ipi, SOFTWARE);
}

void hftest_ipi_init_state_from_message(void *recv_buf, void *send_buf)
{
	uint64_t addr;

	addr = hftest_int_state_page_setup(recv_buf, send_buf);
	hftest_ipi_init_state_through_ptr((uintptr_t)addr);
}

/* Function to share page for the ipi state structure. */
void hftest_ipi_state_share_page_and_init(uint64_t page,
					  ffa_id_t receivers_ids[],
					  size_t receivers_count,
					  void *send_buf)
{
	share_page_with_endpoints(page, receivers_ids, receivers_count,
				  send_buf);

	/* Initialize the state machine to the top of the page. */
	hftest_ipi_init_state_through_ptr((uintptr_t)page);
}
