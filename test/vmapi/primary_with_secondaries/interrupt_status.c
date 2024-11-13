/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "interrupt_status.h"

#include "hf/mm.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * To free the RX buffer as soon as possible,
 * and store the information of the memory region
 * for the interrupt status.
 */
extern uint8_t retrieve_buffer[PAGE_SIZE * 2];

/* Pointer tracking trusted watchdog interrupt status. */
volatile uint32_t *twdog_status;

void hftest_interrupt_status_set(uint32_t status)
{
	*twdog_status = status;
}

uint32_t hftest_interrupt_status_get(void)
{
	return *twdog_status;
}

/* Initialize the interrupt status variable at the top of the page. */
static void hftest_interrupt_status_track(uintptr_t addr)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	twdog_status = (uint32_t *)addr;
}

void hftest_interrupt_status_page_setup(void *recv_buf, void *send_buf)
{
	uint64_t addr;

	addr = get_shared_page_from_message(recv_buf, send_buf,
					    retrieve_buffer);
	hftest_interrupt_status_track(addr);
}

void hftest_interrupt_status_share_page_and_init(uint64_t page,
						 ffa_id_t receivers_ids[],
						 size_t receivers_count,
						 void *send_buf)
{
	share_page_with_endpoints(page, receivers_ids, receivers_count,
				  send_buf);
	hftest_interrupt_status_track(page);

	/* Initialize the interrupt status now to RESET. */
	hftest_interrupt_status_set(INTR_RESET);
}
