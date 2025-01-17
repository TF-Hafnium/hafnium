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

/*
 * Global IPI states used the functions below.
 */
static struct hftest_int_state *ipi_states;
/*
 * The index into the ipi state array the service is currently using.
 */
static uint32_t current_ipi_state_index;
/*
 * When sharing the same ipi state to multiple CPUs it must only be initialized
 * once. This bool tracks if the state has already been initializzed.
 */
atomic_bool ipi_state_initialized = false;

static bool is_ipi_state_initialized(void)
{
	return atomic_load_explicit(&ipi_state_initialized,
				    memory_order_relaxed);
}

static void set_ipi_state_initialized(void)
{
	atomic_store_explicit(&ipi_state_initialized, true,
			      memory_order_relaxed);
}

bool hftest_ipi_state_is(enum int_state to_check)
{
	return hftest_int_state_is(&ipi_states[current_ipi_state_index],
				   to_check);
}

static void hftest_ipi_state_set_at_index(enum int_state to_set,
					  uint32_t ipi_state_index)
{
	struct hftest_int_state *ipi_state = &ipi_states[ipi_state_index];
	hftest_int_state_set(ipi_state, to_set);
	if (to_set == INIT) {
		hftest_int_state_reset_interrupt_count(ipi_state);
	}
}

void hftest_ipi_state_set(enum int_state to_set)
{
	hftest_ipi_state_set_at_index(to_set, current_ipi_state_index);
}

uint32_t hftest_ipi_state_get_interrupt_count(void)
{
	return hftest_int_state_get_interrupt_count(
		&ipi_states[current_ipi_state_index]);
}

/* Set the state of all the IPI States to READY. */
void hftest_ipi_state_set_all_ready(void)
{
	for (uint32_t i = 0; i < MAX_CPUS; i++) {
		hftest_ipi_state_set_at_index(READY, i);
	}
}

void hftest_ipi_state_reset_all(void)
{
	for (uint32_t i = 0; i < MAX_CPUS; i++) {
		hftest_ipi_state_set_at_index(INIT, i);
	}
}

static void hftest_ipi_init_state_through_ptr(uintptr_t addr)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ipi_states = (struct hftest_int_state *)addr;

	/* Initialise both variables for all elements in the array. */
	for (int i = 0; i < MAX_CPUS; i++) {
		hftest_int_state_init(&ipi_states[i], SOFTWARE);
	}
}

void hftest_ipi_init_state_from_message(void *recv_buf, void *send_buf)
{
	uint64_t addr;
	struct ffa_value ret;

	if (is_ipi_state_initialized()) {
		HFTEST_LOG("IPI state already initialized for this service.\n");
		return;
	}

	addr = hftest_int_state_page_setup(recv_buf, send_buf);
	hftest_ipi_init_state_through_ptr((uintptr_t)addr);
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Receive the index of the ipi state array the service should use. */
	receive_indirect_message((void *)&current_ipi_state_index,
				 sizeof(current_ipi_state_index), recv_buf);

	set_ipi_state_initialized();

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);
}

/**
 * Function to share page for the ipi state structure.
 * ipi_state_indexes stores the index for the ipi_states array each receiver
 * listed in the receiver_ids list should use for test coordination.
 */
ffa_memory_handle_t hftest_ipi_state_share_page_and_init(
	uint64_t page, ffa_id_t receivers_ids[],
	uint32_t receivers_ipi_state_indexes[], size_t receivers_count,
	void *send_buf, uint32_t vcpu_id)
{
	struct ffa_value ret;
	ffa_memory_handle_t handle;

	if (is_ipi_state_initialized()) {
		return FFA_MEMORY_HANDLE_INVALID;
	}

	handle = share_page_with_endpoints(page, receivers_ids, receivers_count,
					   send_buf);

	/* Initialize the state machine to the top of the page. */
	hftest_ipi_init_state_through_ptr((uintptr_t)page);

	for (size_t i = 0; i < receivers_count; i++) {
		/*
		 * Resume service in target vCPU0 to retrieve memory and
		 * configure the IPI state.
		 */
		ret = ffa_run(receivers_ids[i], vcpu_id);
		EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

		/*
		 * Send the index of the ipi_state array the receiver should
		 * use for test coordination.
		 */
		ret = send_indirect_message(
			hf_vm_get_id(), receivers_ids[i], send_buf,
			&receivers_ipi_state_indexes[i],
			sizeof(receivers_ipi_state_indexes[0]), 0);

		ASSERT_EQ(ret.func, FFA_SUCCESS_32);

		EXPECT_EQ(ffa_run(receivers_ids[i], vcpu_id).func,
			  FFA_MSG_WAIT_32);
	}

	set_ipi_state_initialized();

	return handle;
}

void hftest_ipi_state_page_relinquish(void *send_buf)
{
	hftest_int_state_page_relinquish(send_buf);
}
