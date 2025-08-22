/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/mmio.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "sp_helpers.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

#define ILLEGAL_ADDR 5
uint8_t sp_retrieve_buffer[PAGE_SIZE * 2];

alignas(PAGE_SIZE) static uint8_t lend_page[PAGE_SIZE];

static void irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();

	if (intid == IRQ_TWDOG_INTID) {
		HFTEST_LOG("Received Trusted WatchDog Interrupt: %u.", intid);
		twdog_stop();
	} else if (intid == HF_NOTIFICATION_PENDING_INTID) {
		/* RX buffer full notification. */
		HFTEST_LOG("Received notification pending interrupt %u.",
			   intid);
	} else {
		panic("Invalid interrupt received: %u\n", intid);
	}
}

/**
 * Exception handler used by an S-EL1 partition to voluntarily terminate
 * execution upon fatal error.
 */
static bool exception_handler_abort_execution(void)
{
	dlog("Aborting after fatal synchronous exception\n");

	ffa_abort_32(0);

	return true;
}

TEST_SERVICE(sp_ffa_abort_dir_req)
{
	struct ffa_value args;

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	args = ffa_msg_wait();

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	ffa_abort_32(0);

	FAIL("Not expected to return after FFA_ABORT");
}

TEST_SERVICE(sp_ffa_abort_indirect_message)
{
	struct ffa_value args;
	uint32_t payload;
	void *recv_buf = SERVICE_RECV_BUFFER();

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	args = ffa_msg_wait();
	EXPECT_EQ(args.func, FFA_RUN_32);

	receive_indirect_message((void *)&payload, sizeof(payload), recv_buf);

	HFTEST_LOG("Echo payload: %u", payload);
	ffa_abort_32(0);

	FAIL("Not expected to return after stopping");
}

TEST_SERVICE(sp_fatal_error_sync_exception)
{
	struct ffa_value args = ffa_msg_wait();

	exception_setup(NULL, exception_handler_abort_execution);

	EXPECT_EQ(args.func, FFA_MSG_SEND_DIRECT_REQ_32);

	/*
	 * Cause a synchronous exception by writing to an illegal address,
	 * thereby emulating a fatal error for SP. This causes the SP to be
	 * aborted.
	 */
	mmio_write32((void *)ILLEGAL_ADDR, 0x9999);

	FAIL("Not expected to return after fatal error");
}

TEST_SERVICE(sp_to_sp_dir_req_abort_start_another_dir_req)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	ffa_id_t target_id;
	ffa_id_t companion_id;

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Retrieve FF-A ID of the target endpoint. */
	receive_indirect_message((void *)&target_id, sizeof(target_id),
				 recv_buf);

	res = ffa_msg_send_direct_req(hf_vm_get_id(), target_id, msg[0], msg[1],
				      msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_ABORTED);

	dlog_verbose("Yield to PVM\n");
	ffa_yield();

	receive_indirect_message((void *)&companion_id, sizeof(companion_id),
				 recv_buf);

	/* Retrieve FF-A ID of the companion endpoint. */
	dlog_verbose("Echo test with: %x", companion_id);

	res = ffa_msg_send_direct_req(hf_vm_get_id(), companion_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);

	ffa_yield();
}

TEST_SERVICE(sp_to_sp_dir_req_expect_to_abort)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	ffa_id_t target_id;

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Retrieve FF-A ID of the target endpoint. */
	receive_indirect_message((void *)&target_id, sizeof(target_id),
				 recv_buf);

	res = ffa_msg_send_direct_req(hf_vm_get_id(), target_id, msg[0], msg[1],
				      msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_ABORTED);

	/* Yield cycles to PVM. */
	ffa_yield();
}

TEST_SERVICE(sp_active_wait)
{
	uint32_t waitms;
	void *recv_buf = SERVICE_RECV_BUFFER();

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	receive_indirect_message((void *)&waitms, sizeof(waitms), recv_buf);

	ffa_msg_wait();

	dlog_verbose("Start active wait of %ums\n", waitms);
	sp_wait(waitms);
	dlog_verbose("End active wait of %ums\n", waitms);

	/* Yield cycles to PVM. */
	ffa_yield();
}

static ffa_memory_handle_t memory_retrieve_and_access(void)
{
	size_t i;
	ffa_memory_handle_t handle;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)sp_retrieve_buffer;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region_constituent *constituents;

	exception_setup(NULL, exception_handler_yield_data_abort);
	retrieve_memory_from_message(recv_buf, send_buf, &handle, memory_region,
				     sizeof(sp_retrieve_buffer));
	composite = ffa_memory_region_get_composite(memory_region, 0);

	/* ASSERT_TRUE isn't enough for clang-analyze. */
	CHECK(composite != NULL);
	constituents = composite->constituents;

	update_mm_security_state(composite, memory_region->attributes);

	/*
	 * Check that we can read and write every page that was shared.
	 */
	for (i = 0; i < composite->constituent_count; ++i) {
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		uint8_t *ptr = (uint8_t *)constituents[i].address;
		uint32_t count = constituents[i].page_count;
		size_t j;

		for (j = 0; j < PAGE_SIZE * count; ++j) {
			ptr[j]++;
		}
	}

	return handle;
}

TEST_SERVICE(ffa_memory_retrieve_abort)
{
	memory_retrieve_and_access();

	/*
	 * The partition encounters a fatal error while handling a memory
	 * management transaction. It does not have the chance to
	 * relinquish the access to memory region back to owner.
	 */
	ffa_abort_32(0);

	FAIL("Not expected to return after aborting");
}

TEST_SERVICE(ffa_memory_retrieve_relinquish)
{
	ffa_memory_handle_t handle = memory_retrieve_and_access();
	void *send_buf = SERVICE_SEND_BUFFER();

	/* Give the memory back and notify the sender. */
	ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
	EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
}

/**
 * Lend a normal memory page from this SP to a companion SP and then abort.
 * The companion FF-A ID is provided by the primary via an indirect message.
 * After the primary lends memory to this SP, we relay it to the companion via
 * LEND and abort to exercise SPMC reclaim on behalf of the lender.
 */
TEST_SERVICE(ffa_lend_memory_to_companion_sp_and_abort)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	ffa_id_t companion_id;
	struct ffa_value ret;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&lend_page, .page_count = 1},
	};

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Receive the companion endpoint to which we should lend. */
	receive_indirect_message(&companion_id, sizeof(companion_id), recv_buf);

	/* Lend a page to the companion and request it to retrieve. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), companion_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Give back control to PVM. */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/*
	 * Abort without reclaiming the lent memory; SPMC should clean up on
	 * behalf of this partition.
	 */
	ffa_abort_32(0);

	FAIL("Not expected to return after aborting");
}
