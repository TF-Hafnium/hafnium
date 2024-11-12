/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "ipi_state.h"

#include "hf/mm.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/* Default global state for IPI. */
static struct hftest_ipi ipi = {
	.state = INIT,
	.lock = SPINLOCK_INIT,
};

/*
 * Global IPI state used the functions below.
 */
static struct hftest_ipi *current_ipi;

/*
 * To free the RX buffer as soon as possible,
 * and store the information of the memory region
 * for the ipi_state.
 */
extern uint8_t retrieve_buffer[PAGE_SIZE * 2];

bool hftest_ipi_state_is(enum ipi_state to_check)
{
	bool result;

	sl_lock(&current_ipi->lock);

	result = to_check == current_ipi->state;

	sl_unlock(&current_ipi->lock);

	return result;
}

void hftest_ipi_state_set(enum ipi_state to_set)
{
	assert(current_ipi != NULL);

	sl_lock(&current_ipi->lock);

	switch (current_ipi->state) {
	case INIT:
		if (to_set != READY) {
			panic("%s: current state: INIT expected next state: "
			      "READY.",
			      __func__);
		}
		break;
	case READY:
		if (to_set != SENT) {
			panic("%s: current state: READY expected next state: "
			      "SENT.",
			      __func__);
		}
		break;
	case SENT:
		if (to_set != HANDLED) {
			panic("%s: current state: SENT expected next state: "
			      "HANDLED.",
			      __func__);
		}
		break;
	case HANDLED:
		if (to_set != READY) {
			panic("%s: current state: HANDLED expected next state: "
			      "READY.",
			      __func__);
		}
		break;
	default:
		panic("%s: unknown current_ipi->state %u", __func__,
		      current_ipi->state);
	}

	current_ipi->state = to_set;

	sl_unlock(&current_ipi->lock);
}

void hftest_ipi_init_state_default(void)
{
	current_ipi = &ipi;
}

static void hftest_ipi_init_state_through_ptr(uintptr_t addr)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	current_ipi = (struct hftest_ipi *)addr;

	/* Initialise both variables. */
	sl_init(&current_ipi->lock);
	current_ipi->state = INIT;
}

void hftest_ipi_init_state_from_message(void *recv_buf, void *send_buf)
{
	uint64_t addr;

	addr = get_shared_page_from_message(recv_buf, send_buf,
					    retrieve_buffer);
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
