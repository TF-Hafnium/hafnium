/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "int_state.h"

#include "hf/mm.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * To free the RX buffer as soon as possible,
 * and store the information of the memory region
 * for the interrupt status.
 */
extern uint8_t retrieve_buffer[PAGE_SIZE * 2];

ffa_memory_handle_t memory_handle;

bool hftest_int_state_is(struct hftest_int_state *track,
			 enum int_state to_check)
{
	bool result;

	sl_lock(&track->lock);

	result = to_check == track->state;

	sl_unlock(&track->lock);

	return result;
}

void hftest_int_state_set(struct hftest_int_state *track, enum int_state to_set)
{
	enum int_category category;
	assert(track != NULL);

	category = track->category;
	sl_lock(&track->lock);

	/* Always allow the test to be reset back to INIT. */
	if (to_set != INIT) {
		/* The transitions supported depend on the category of the
		 * interrupt. */
		switch (track->state) {
		case INIT:
			if (category == SOFTWARE && to_set != READY) {
				panic("%s: current state: INIT expected next "
				      "state: READY.",
				      __func__);
			} else if (category == HARDWARE && to_set != SENT) {
				panic("%s: current state: INIT expected next "
				      "state: SENT.",
				      __func__);
			}
			break;
		case READY:
			if (category == HARDWARE) {
				panic("%s: READY state is illegal for HARDWARE "
				      "interrupt.",
				      __func__);

			} else if (to_set != SENT) {
				panic("%s: current state: READY expected next "
				      "state: SENT.",
				      __func__);
			}
			break;
		case SENT:
			if (to_set != HANDLED) {
				panic("%s: current state: SENT expected next "
				      "state: HANDLED.",
				      __func__);
			}
			break;
		case HANDLED:
			if (to_set != READY && to_set != HANDLED) {
				panic("%s: current state: HANDLED expected "
				      "next state: READY or HANDLED.",
				      __func__);
			}
			break;
		default:
			panic("%s: unknown state %u", __func__, track->state);
		}
	}

	track->state = to_set;
	if (to_set == HANDLED) {
		track->interrupt_count++;
	}

	sl_unlock(&track->lock);
}

uint32_t hftest_int_state_get_interrupt_count(struct hftest_int_state *track)
{
	uint32_t interrupt_count;
	sl_lock(&track->lock);

	interrupt_count = track->interrupt_count;

	sl_unlock(&track->lock);

	return interrupt_count;
}

void hftest_int_state_reset_interrupt_count(struct hftest_int_state *track)
{
	sl_lock(&track->lock);

	track->interrupt_count = 0;

	sl_unlock(&track->lock);
}

void hftest_int_state_init(struct hftest_int_state *track,
			   enum int_category category)
{
	assert(track != NULL);

	/* Initialise relevant variables. */
	sl_init(&track->lock);
	track->state = INIT;
	track->category = category;
}

uint64_t hftest_int_state_page_setup(void *recv_buf, void *send_buf)
{
	uint64_t addr;

	addr = get_shared_page_from_message(recv_buf, send_buf, retrieve_buffer,
					    &memory_handle);
	return addr;
}

void hftest_int_state_page_relinquish(void *send_buf)
{
	ffa_mem_relinquish_init(send_buf, memory_handle, 0, hf_vm_get_id());

	EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
}
