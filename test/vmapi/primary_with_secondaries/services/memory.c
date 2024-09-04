/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/mmu.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vmid_base.h"

#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/mm.h"
#include "hf/std.h"
#include "hf/types.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa_v1_0.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t page[PAGE_SIZE];
/**
 * Used for memory sharing operations in both the memory sharing
 * and IPI tests.
 */
uint8_t retrieve_buffer[PAGE_SIZE * 2];

static void memory_increment(ffa_memory_handle_t *handle,
			     bool check_not_cleared)
{
	uint32_t i;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	struct ffa_memory_access *receiver;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;
	/* Variable to detect if retrieved page was used before. */
	bool page_used = false;

	retrieve_memory_from_message(recv_buf, send_buf, NULL, memory_region,
				     HF_MAILBOX_SIZE);
	receiver = ffa_memory_region_get_receiver(memory_region, 0);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;

	ASSERT_EQ(memory_region->receiver_count, 1);
	ASSERT_TRUE(receiver != NULL);
	ASSERT_NE(receiver->composite_memory_region_offset, 0);

	update_mm_security_state(composite, memory_region->attributes);

	if (handle != NULL) {
		*handle = memory_region->handle;
	}

	/* Allow the memory to be populated. */
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

	/* Increment each byte of memory. */
	for (i = 0; i < PAGE_SIZE; i++) {
		/* Check that memory is not cleared before incrementing. */
		if (check_not_cleared) {
			page_used = page_used || (ptr[i] != 0U);
		}
		++ptr[i];
	}

	/*
	 * In case 'check_not_cleared' was provided as true in the arguments,
	 * during iteration over content of the page, 'page_used' captures if
	 * there was any value different from 0. This is an indication that
	 * memory hasn't been cleared before use in the context of the running
	 * partition.
	 */
	if (check_not_cleared) {
		EXPECT_TRUE(page_used);
	}

	/* Return control to primary. */
	ffa_yield();
}

TEST_SERVICE(memory_increment)
{
	/* Loop, writing message to the shared memory. */
	for (;;) {
		memory_increment(NULL, false);
	}
}

TEST_SERVICE(memory_increment_relinquish)
{
	/* Loop, writing message to the shared memory. */
	for (;;) {
		ffa_memory_handle_t handle;

		memory_increment(&handle, false);

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(SERVICE_SEND_BUFFER(), handle, 0,
					hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);

		/* Signal completion and reset. */
		ffa_yield();
	}
}

TEST_SERVICE(memory_increment_relinquish_with_clear)
{
	/* Loop, writing message to the shared memory. */
	for (;;) {
		ffa_memory_handle_t handle;

		memory_increment(&handle, false);

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(SERVICE_SEND_BUFFER(), handle,
					FFA_MEMORY_REGION_FLAG_CLEAR,
					hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);

		/* Signal completion and reset. */
		ffa_yield();
	}
}

TEST_SERVICE(memory_increment_relinquish_with_clear_check_not_zeroed)
{
	/* Loop, writing message to the shared memory. */
	for (;;) {
		ffa_memory_handle_t handle;

		memory_increment(&handle, true);

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(SERVICE_SEND_BUFFER(), handle,
					FFA_MEMORY_REGION_FLAG_CLEAR,
					hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);

		/* Return control to primary. */
		ffa_yield();
	}
}

TEST_SERVICE(memory_increment_check_mem_attr)
{
	enum ffa_memory_type type;
	enum ffa_memory_shareability shareability;
	enum ffa_memory_cacheability cacheability;

	/* Loop, writing message to the shared memory. */
	for (;;) {
		size_t i;
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		retrieve_memory_from_message(recv_buf, send_buf, NULL,
					     memory_region, HF_MAILBOX_SIZE);
		struct ffa_memory_access *receiver =
			ffa_memory_region_get_receiver(memory_region, 0);
		struct ffa_composite_memory_region *composite =
			ffa_memory_region_get_composite(memory_region, 0);
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		uint8_t *ptr = (uint8_t *)composite->constituents[0].address;

		ASSERT_EQ(memory_region->receiver_count, 1);
		ASSERT_TRUE(receiver != NULL);
		ASSERT_NE(receiver->composite_memory_region_offset, 0);

		update_mm_security_state(composite, memory_region->attributes);

		/*
		 * Validate retrieve response contains the memory attributes
		 * hafnium implements.
		 */
		type = memory_region->attributes.type;
		shareability = memory_region->attributes.shareability;
		cacheability = memory_region->attributes.cacheability;
		ASSERT_EQ(type, FFA_MEMORY_NORMAL_MEM);
		ASSERT_EQ(shareability, FFA_MEMORY_INNER_SHAREABLE);
		ASSERT_EQ(cacheability, FFA_MEMORY_CACHE_WRITE_BACK);

		/* Increment each byte of memory. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			++ptr[i];
		}

		/* Return control to primary. */
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
	}
}

TEST_SERVICE(give_memory_and_fault)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};

	/* Give memory to the primary. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, send_buf, hf_vm_get_id(), HF_PRIMARY_VM_ID,
		constituents, ARRAY_SIZE(constituents),
		FFA_MEMORY_REGION_FLAG_CLEAR, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();

	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Try using the memory that isn't valid unless it's been returned. */
	page[16] = 123;

	FAIL("Exception not generated by invalid access.");
}

TEST_SERVICE(lend_memory_and_fault)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};

	/* Lend memory to the primary. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), HF_PRIMARY_VM_ID,
		constituents, ARRAY_SIZE(constituents),
		FFA_MEMORY_REGION_FLAG_CLEAR, 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();

	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Try using the memory that isn't valid unless it's been returned. */
	page[633] = 180;

	FAIL("Exception not generated by invalid access.");
}

/**
 * Test that a sender looses access to device memory once
 * it has lent it.
 */
TEST_SERVICE(ffa_lend_device_memory_secondary_and_fault)
{
	volatile uint8_t *ptr;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct hftest_context *ctx = hftest_get_context();
	uintptr_t device_mem_base_addr =
		ctx->partition_manifest.dev_regions[0].base_address;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)device_mem_base_addr, .page_count = 1},
	};

	ASSERT_TRUE(ctx->partition_manifest.dev_region_count > 0);

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)device_mem_base_addr;

	/* Try write to the memory before sharing. */
	ptr[0] = 'b';

	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Lend memory to Service2 SP. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_DEV_NGNRNE);

	ffa_yield();

	/* Ensure that we are unable to modify memory any more. */
	ptr[0] = 'c';

	FAIL("Exception not generated by invalid access.");
}

/**
 *  Test that normal memory can be shared with the device memory type
 *  successfully, and that the sender loses access to the memory region
 *  once it has lent it.
 */
TEST_SERVICE(ffa_lend_normal_memory_as_device_secondary_and_fault)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};

	/* Try write to the memory before sharing. */
	page[0] = 'b';

	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Lend memory to Service2 SP. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_DEV_NGNRNE);

	ffa_yield();

	/* Ensure that we are unable to modify memory any more. */
	page[0] = 'c';

	FAIL("Exception not generated by invalid access.");
}

/**
 * Receive the lent device memory and write to the base address.
 */
TEST_SERVICE(ffa_memory_lend_relinquish_device)
{
	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Loop, giving memory back to the sender. */
	for (;;) {
		size_t i;
		ffa_memory_handle_t handle;
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		struct ffa_composite_memory_region *composite;
		struct ffa_memory_region_constituent *constituents;
		volatile uint8_t *first_ptr;
		volatile uint8_t *ptr;

		retrieve_memory_from_message(recv_buf, send_buf, &handle,
					     memory_region,
					     sizeof(retrieve_buffer));
		composite = ffa_memory_region_get_composite(memory_region, 0);
		/* ASSERT_TRUE isn't enough for clang-analyze. */
		CHECK(composite != NULL);

		constituents = composite->constituents;
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		first_ptr = (uint8_t *)constituents[0].address;

		update_mm_security_state(composite, memory_region->attributes);

		/*
		 * Check that we can read and write every page that was shared.
		 */
		for (i = 0; i < composite->constituent_count; ++i) {
			// NOLINTNEXTLINE(performance-no-int-to-ptr)
			ptr = (uint8_t *)constituents[i].address;
			ptr[0] = 'w';
			ptr[0] = 'o';
			ptr[0] = 'r';
			ptr[0] = 'l';
			ptr[0] = 'd';
			ptr[0] = '\n';
		}

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

		/*
		 * Try to access the memory, which will cause a fault unless the
		 * memory has been shared back again.
		 */
		first_ptr[0] = 123;
	}
}

/**
 * Validate the lent device memory cannot be retrieve as normal memory as this
 * breaks the memory type precedence rules given in the FF-A v1.2 ALP0
 * specification section 11.10.4.
 */
TEST_SERVICE(ffa_lend_device_memory_to_sp_as_normal)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct hftest_context *ctx = hftest_get_context();
	uintptr_t device_mem_base_addr =
		ctx->partition_manifest.dev_regions[0].base_address;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)device_mem_base_addr, .page_count = 1},
	};

	/*
	 * Lend device memory to next VM with the memory type in the retrieve
	 * request set to Normal memory. This should fail.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();
}

/**
 * Attempt to lend device memory to another SP, reclaim it and check the
 * SP we can access it again.
 * The device memory shared is UART1 so the output can be viewed in the test
 * logs.
 */
TEST_SERVICE(ffa_lend_device_memory_to_sp_and_reclaim)
{
	volatile uint8_t *ptr;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct hftest_context *ctx = hftest_get_context();
	uintptr_t device_mem_base_addr =
		ctx->partition_manifest.dev_regions[0].base_address;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)device_mem_base_addr, .page_count = 1},
	};
	ffa_memory_handle_t handle;

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)device_mem_base_addr;

	/* Try write to the memory before sharing. */
	ptr[0] = 'h';
	ptr[0] = 'e';
	ptr[0] = 'l';
	ptr[0] = 'l';
	ptr[0] = 'o';
	ptr[0] = '\n';

	/* Lend memory to next VM. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_DEV_NGNRNE);

	ffa_yield();

	ASSERT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	ptr[0] = 'h';
	ptr[0] = 'i';
	ptr[0] = '\n';

	ffa_yield();
}

/**
 * Test that device memory cannot be donated or shared. And lending to
 * multiple borrowers is not permitted.
 */
TEST_SERVICE(ffa_lend_device_memory_fails)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_partition_info *service3_info = service3(recv_buf);
	struct hftest_context *ctx = hftest_get_context();
	uintptr_t device_mem_base_addr =
		ctx->partition_manifest.dev_regions[0].base_address;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)device_mem_base_addr, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_memory_access receivers[2];
	struct ffa_memory_access_impdef zeroed_impdef_val =
		ffa_memory_access_impdef_init(0, 0);

	ASSERT_TRUE(ctx->partition_manifest.dev_region_count > 0);

	/* If the service partition is not an SP, do not execute. */
	ASSERT_TRUE(!ffa_is_vm_id(hf_vm_get_id()));

	/*
	 * Memory type can't be set in the attributes on FFA_MEM_DONATE.
	 */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  send_buf, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service2_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEV_NGNRNE,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  send_buf, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service2_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_DEVICE_MEM, FFA_MEMORY_DEV_NGNRNE,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size), FFA_DENIED);

	/* Test lending multiple borrowers is not permitted. */
	ffa_memory_access_init(
		&receivers[0], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &zeroed_impdef_val);
	ffa_memory_access_init(
		&receivers[1], service3_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &zeroed_impdef_val);

	/*
	 * Memory type can't be set in the attributes on FFA_MEM_LEND.
	 */
	ffa_memory_region_init(
		send_buf, HF_MAILBOX_SIZE, hf_vm_get_id(), receivers,
		ARRAY_SIZE(receivers), sizeof(struct ffa_memory_access),
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEV_NGNRNE,
		FFA_MEMORY_INNER_SHAREABLE, &msg_size, NULL);

	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);

	ffa_yield();
}

TEST_SERVICE(ffa_memory_return)
{
	uint8_t *ptr;
	size_t i;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	ffa_id_t target_id;
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	ffa_id_t sender;
	struct ffa_composite_memory_region *composite;

	receive_indirect_message(&target_id, sizeof(target_id), recv_buf,
				 &sender);

	ffa_yield();

	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Expect same sender as the previous indirect message. */
	EXPECT_EQ(retrieve_memory_from_message(recv_buf, send_buf, NULL,
					       memory_region, HF_MAILBOX_SIZE),
		  sender);

	composite = ffa_memory_region_get_composite(memory_region, 0);

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;

	update_mm_security_state(composite, memory_region->attributes);

	/* Check that one has access to the shared region. */
	for (i = 0; i < PAGE_SIZE; ++i) {
		ptr[i]++;
	}

	/* Give the memory back and notify the target_id. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, send_buf, hf_vm_get_id(), target_id,
		composite->constituents, composite->constituent_count, 0, 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();

	/*
	 * Try and access the memory which will cause a fault unless the memory
	 * has been shared back again.
	 */
	ptr[0] = 123;

	FAIL("Exception not generated by invalid access.");
}

/**
 * Attempt to modify above the upper bound of a memory region sent to us.
 */
TEST_SERVICE(ffa_check_upper_bound)
{
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;
	uint8_t index;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	exception_setup(NULL, exception_handler_yield_data_abort);

	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	retrieve_memory_from_message(recv_buf, send_buf, NULL, memory_region,
				     HF_MAILBOX_SIZE);
	composite = ffa_memory_region_get_composite(memory_region, 0);

	update_mm_security_state(composite, memory_region->attributes);

	/* Choose which constituent we want to test. */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	index = *(uint8_t *)composite->constituents[0].address;
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[index].address;

	/*
	 * Check that we can't access out of bounds after the region sent to us.
	 * This should trigger the exception handler.
	 */
	ptr[PAGE_SIZE]++;

	FAIL("Exception not generated by access out of bounds.");
}

/**
 * Attempt to modify below the lower bound of a memory region sent to us.
 */
TEST_SERVICE(ffa_check_lower_bound)
{
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;
	uint8_t index;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	exception_setup(NULL, exception_handler_yield_data_abort);

	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	retrieve_memory_from_message(recv_buf, send_buf, NULL, memory_region,
				     HF_MAILBOX_SIZE);

	composite = ffa_memory_region_get_composite(memory_region, 0);

	update_mm_security_state(composite, memory_region->attributes);

	/* Choose which constituent we want to test. */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	index = *(uint8_t *)composite->constituents[0].address;
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[index].address;

	/*
	 * Check that we can't access out of bounds before the region sent to
	 * us. This should trigger the exception handler.
	 */
	ptr[-1]++;

	FAIL("Exception not generated by access out of bounds.");
}

/**
 * Attempt to donate memory and then modify.
 */
TEST_SERVICE(ffa_donate_secondary_and_fault)
{
	uint8_t *ptr;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};

	exception_setup(NULL, exception_handler_yield_data_abort);

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)page;

	/* Donate memory to next VM. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, send_buf, hf_vm_get_id(),
		service2_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();

	/* Ensure that we are unable to modify memory any more. */
	ptr[0] = 'c';

	FAIL("Exception not generated by invalid access.");
}

/**
 * Attempt to donate memory twice from VM.
 */
TEST_SERVICE(ffa_donate_twice)
{
	uint32_t msg_size;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	ffa_id_t sender;
	ffa_id_t target_id;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region_constituent constituent;

	receive_indirect_message(&target_id, sizeof(target_id), recv_buf,
				 &sender);

	ffa_yield();
	EXPECT_EQ(retrieve_memory_from_message(recv_buf, send_buf, NULL,
					       memory_region, HF_MAILBOX_SIZE),
		  sender);

	composite = ffa_memory_region_get_composite(memory_region, 0);
	constituent = composite->constituents[0];

	/* Yield to allow attempt to re donate from primary. */
	ffa_yield();

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, send_buf, hf_vm_get_id(), target_id,
		&constituent, 1, 0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();

	/* Attempt to donate the memory again. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  send_buf, HF_MAILBOX_SIZE, hf_vm_get_id(), target_id,
			  &constituent, 1, 0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);

	ffa_yield();
}

/**
 * Continually receive memory, check if we have access and ensure it is not
 * changed by a third party.
 */
TEST_SERVICE(ffa_memory_receive)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	for (;;) {
		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		struct ffa_composite_memory_region *composite;
		uint8_t *ptr;

		retrieve_memory_from_message(recv_buf, send_buf, NULL,
					     memory_region, HF_MAILBOX_SIZE);
		composite = ffa_memory_region_get_composite(memory_region, 0);
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		ptr = (uint8_t *)composite->constituents[0].address;

		update_mm_security_state(composite, memory_region->attributes);

		ptr[0] = 'd';
		ffa_yield();

		/* Ensure memory has not changed. */
		EXPECT_EQ(ptr[0], 'd');
		ffa_yield();
	}
}

/**
 * Receive memory and attempt to donate from primary VM.
 */
TEST_SERVICE(ffa_donate_invalid_source)
{
	uint32_t msg_size;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	ffa_id_t sender = retrieve_memory_from_message(
		recv_buf, send_buf, NULL, memory_region, HF_MAILBOX_SIZE);
	struct ffa_composite_memory_region *composite =
		ffa_memory_region_get_composite(memory_region, 0);

	/* Give the memory back and notify the sender. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, send_buf, hf_vm_get_id(), sender,
		composite->constituents, composite->constituent_count, 0, 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();

	/* Fail to donate the memory from the primary to VM2. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  send_buf, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  service2(recv_buf)->vm_id, composite->constituents,
			  composite->constituent_count, 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);
	ffa_yield();
}

TEST_SERVICE(ffa_memory_lend_relinquish_relend)
{
	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Loop, giving memory back to the sender. */
	for (;;) {
		size_t i;
		ffa_memory_handle_t handle;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		struct ffa_composite_memory_region *composite;
		struct ffa_memory_region_constituent *constituents;

		retrieve_memory_from_message(recv_buf, send_buf, &handle,
					     memory_region,
					     sizeof(retrieve_buffer));
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

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
	}
}

TEST_SERVICE(ffa_memory_lend_relinquish)
{
	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Loop, giving memory back to the sender. */
	for (;;) {
		size_t i;
		ffa_memory_handle_t handle;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		struct ffa_composite_memory_region *composite;
		struct ffa_memory_region_constituent *constituents;
		uint8_t *first_ptr;

		retrieve_memory_from_message(recv_buf, send_buf, &handle,
					     memory_region,
					     sizeof(retrieve_buffer));
		composite = ffa_memory_region_get_composite(memory_region, 0);
		/* ASSERT_TRUE isn't enough for clang-analyze. */
		CHECK(composite != NULL);
		constituents = composite->constituents;
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		first_ptr = (uint8_t *)constituents[0].address;

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

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

		/*
		 * Try to access the memory, which will cause a fault unless the
		 * memory has been shared back again.
		 */
		first_ptr[0] = 123;
	}
}

/**
 * Ensure that we can't relinquish donated memory.
 */
TEST_SERVICE(ffa_memory_donate_relinquish)
{
	for (;;) {
		size_t i;
		ffa_memory_handle_t handle;
		struct ffa_memory_region *memory_region;
		struct ffa_composite_memory_region *composite;
		uint8_t *ptr;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		memory_region = (struct ffa_memory_region *)retrieve_buffer;
		retrieve_memory_from_message(recv_buf, send_buf, &handle,
					     memory_region, HF_MAILBOX_SIZE);
		composite = ffa_memory_region_get_composite(memory_region, 0);

		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		ptr = (uint8_t *)composite->constituents[0].address;

		update_mm_security_state(composite, memory_region->attributes);

		/* Check that we have access to the shared region. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		/*
		 * Attempt to relinquish the memory, which should fail because
		 * it was donated not lent.
		 */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_FFA_ERROR(ffa_mem_relinquish(), FFA_INVALID_PARAMETERS);

		/* Ensure we still have access to the memory. */
		ptr[0] = 123;

		ffa_yield();
	}
}

/**
 * Receive memory that has been shared, try to relinquish it with the clear flag
 * set (and expect to fail), and then relinquish without any flags.
 */
TEST_SERVICE(ffa_memory_share_relinquish_clear)
{
	exception_setup(NULL, exception_handler_yield_data_abort);

	/* Loop, receiving memory and relinquishing it. */
	for (;;) {
		ffa_memory_handle_t handle;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		retrieve_memory_from_message(recv_buf, send_buf, &handle, NULL,
					     HF_MAILBOX_SIZE);

		/* Trying to relinquish the memory and clear it should fail. */
		ffa_mem_relinquish_init(send_buf, handle,
					FFA_MEMORY_REGION_FLAG_CLEAR,
					hf_vm_get_id());
		EXPECT_FFA_ERROR(ffa_mem_relinquish(), FFA_INVALID_PARAMETERS);

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
	}
}

/**
 * Receive memory and attempt to donate from primary VM.
 */
TEST_SERVICE(ffa_lend_invalid_source)
{
	ffa_memory_handle_t handle;
	uint32_t msg_size;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	struct ffa_composite_memory_region *composite;

	retrieve_memory_from_message(recv_buf, send_buf, &handle, memory_region,
				     HF_MAILBOX_SIZE);
	composite = ffa_memory_region_get_composite(memory_region, 0);

	/* Give the memory back and notify the sender. */
	ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
	EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

	/* Ensure we cannot lend from the primary to another secondary. */
	EXPECT_EQ(
		ffa_memory_region_init_single_receiver(
			send_buf, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			service2(recv_buf)->vm_id, composite->constituents,
			composite->constituent_count, 0, 0, FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NOT_SPECIFIED_MEM,
			FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
			NULL, NULL, &msg_size),
		0);
	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);

	/* Ensure we cannot share from the primary to another secondary. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  send_buf, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  service2(recv_buf)->vm_id, composite->constituents,
			  composite->constituent_count, 0, 0,
			  FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_X,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size), FFA_DENIED);

	ffa_yield();
}

/**
 * Attempt to execute an instruction from the lent memory.
 */
TEST_SERVICE(ffa_memory_lend_relinquish_X)
{
	exception_setup(NULL, exception_handler_yield_instruction_abort);

	for (;;) {
		ffa_memory_handle_t handle;
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		struct ffa_composite_memory_region *composite;
		struct ffa_memory_region_constituent *constituents;
		uint32_t *ptr;

		retrieve_memory_from_message(recv_buf, send_buf, &handle,
					     memory_region, HF_MAILBOX_SIZE);
		composite = ffa_memory_region_get_composite(memory_region, 0);

		/* ASSERT_TRUE isn't enough for clang-analyze. */
		CHECK(composite != NULL);

		constituents = composite->constituents;
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		ptr = (uint32_t *)constituents[0].address;

		update_mm_security_state(composite, memory_region->attributes);

		/*
		 * Verify that the instruction in memory is the encoded RET
		 * instruction.
		 */
		EXPECT_EQ(*ptr, 0xD50324DF);
		EXPECT_EQ(*(ptr + 1), 0xD65F03C0);

		/* Try to execute instruction from the shared memory region. */
		__asm__ volatile("blr %0" ::"r"(ptr));

		/* Release the memory again. */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
	}
}

/**
 * Attempt to retrieve a shared page but expect to fail with FFA_DENIED.
 */
TEST_SERVICE(ffa_memory_share_fail_denied)
{
	for (;;) {
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		retrieve_memory_from_message_expect_fail(recv_buf, send_buf,
							 FFA_DENIED);

		/* Return control to primary. */
		ffa_yield();
	}
}

/**
 * Attempt to retrieve a shared page but expect to fail with
 * FFA_INVALID_PARAMETERS.
 */
TEST_SERVICE(ffa_memory_share_fail_invalid_parameters)
{
	for (;;) {
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		retrieve_memory_from_message_expect_fail(
			recv_buf, send_buf, FFA_INVALID_PARAMETERS);

		/* Return control to primary. */
		ffa_yield();
	}
}

/**
 * Attempt to read and write to a shared page.
 */
TEST_SERVICE(ffa_memory_lend_relinquish_RW)
{
	exception_setup(NULL, exception_handler_yield_data_abort);

	for (;;) {
		ffa_memory_handle_t handle;
		uint8_t *ptr;
		size_t i;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct ffa_memory_region *memory_region =
			(struct ffa_memory_region *)retrieve_buffer;
		struct ffa_composite_memory_region *composite;
		struct ffa_memory_region_constituent constituent_copy;

		retrieve_memory_from_message(recv_buf, send_buf, &handle,
					     memory_region, HF_MAILBOX_SIZE);
		composite = ffa_memory_region_get_composite(memory_region, 0);
		constituent_copy = composite->constituents[0];

		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		ptr = (uint8_t *)constituent_copy.address;

		update_mm_security_state(composite, memory_region->attributes);

		/* Check that we have read access. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			EXPECT_EQ(ptr[i], 'b');
		}

		/* Return control to primary, to verify shared access. */
		ffa_yield();

		/* Attempt to modify the memory. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		/* Give the memory back and notify the sender. */
		ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
		EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
		EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
	}
}

TEST_SERVICE(ffa_memory_lend_twice)
{
	uint8_t *ptr;
	uint32_t msg_size;
	size_t i;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region_constituent constituent_copy;

	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	retrieve_memory_from_message(recv_buf, send_buf, NULL, memory_region,
				     HF_MAILBOX_SIZE);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	constituent_copy = composite->constituents[0];

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)constituent_copy.address;

	update_mm_security_state(composite, memory_region->attributes);

	/* Check that we have read access. */
	for (i = 0; i < PAGE_SIZE; ++i) {
		EXPECT_EQ(ptr[i], 'b');
	}

	/* Attempt to modify the memory. */
	for (i = 0; i < PAGE_SIZE; ++i) {
		ptr[i]++;
	}

	for (i = 1; i < PAGE_SIZE * 2; i++) {
		constituent_copy.address = (uint64_t)ptr + i;

		/* Fail to lend or share the memory from the primary. */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  send_buf, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  service2(recv_buf)->vm_id, &constituent_copy,
				  1, 0, 0, FFA_DATA_ACCESS_RW,
				  FFA_INSTRUCTION_ACCESS_X,
				  FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);
		EXPECT_EQ(
			ffa_memory_region_init_single_receiver(
				send_buf, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				service2(recv_buf)->vm_id, &constituent_copy, 1,
				0, 0, FFA_DATA_ACCESS_RW,
				FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NORMAL_MEM,
				FFA_MEMORY_CACHE_WRITE_BACK,
				FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				&msg_size),
			0);
		EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size), FFA_DENIED);
	}

	/* Return control to primary. */
	ffa_yield();
}

/**
 * Share memory from a v1.1 endpoint to multiple borrowers and check
 * that the endpoints can access and modify it.
 */
TEST_SERVICE(share_ffa_v1_1)
{
	struct ffa_value ret;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_partition_info *service3_info = service3(recv_buf);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)page, .page_count = 1},
	};
	/* v1.1 and v1.0 share the same memory access descriptors. */
	struct ffa_memory_access_v1_0 receivers_v1_1[2];
	uint32_t msg_size;
	struct ffa_partition_msg *retrieve_message = send_buf;
	uint8_t *ptr = page;
	ffa_memory_handle_t handle;

	ffa_memory_access_init_v1_0(&receivers_v1_1[0], service2_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	ffa_memory_access_init_v1_0(&receivers_v1_1[1], service3_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);

	ffa_memory_region_init(
		(struct ffa_memory_region *)send_buf, HF_MAILBOX_SIZE,
		hf_vm_get_id(), (void *)receivers_v1_1,
		ARRAY_SIZE(receivers_v1_1),
		sizeof(struct ffa_memory_access_v1_0), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL,
		&msg_size);

	EXPECT_NE(ffa_version(FFA_VERSION_1_1), FFA_ERROR_32);

	ret = ffa_mem_share(msg_size, msg_size);

	handle = ffa_mem_success_handle(ret);

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		hf_vm_get_id(), (void *)receivers_v1_1,
		ARRAY_SIZE(receivers_v1_1),
		sizeof(struct ffa_memory_access_v1_0), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	ffa_rxtx_header_init(hf_vm_get_id(), service2_info->vm_id, msg_size,
			     &retrieve_message->header);
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);

	/* Run service2 for it to fetch the memory. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ptr[i] = i;
	}

	/* Run service2 for it to increment the memory. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		EXPECT_EQ(ptr[i], i + 1);
	}

	ffa_yield();
}

TEST_SERVICE(retrieve_ffa_v1_1)
{
	uint8_t *ptr = NULL;
	uint32_t msg_size;
	size_t i;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	struct ffa_composite_memory_region *composite;
	const struct ffa_partition_msg *retrv_message =
		(struct ffa_partition_msg *)recv_buf;
	struct ffa_value ret;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t memory_region_max_size = HF_MAILBOX_SIZE;

	/* Set version to v1.1. */
	ffa_version(FFA_VERSION_1_1);

	receive_indirect_message(send_buf, HF_MAILBOX_SIZE, recv_buf, NULL);
	msg_size = retrv_message->header.size;
	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_MEM_RETRIEVE_RESP_32);
	fragment_length = ret.arg2;
	total_length = ret.arg1;

	memcpy_s(memory_region, memory_region_max_size, recv_buf,
		 fragment_length);

	/* Copy first fragment. */
	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	memory_region_desc_from_rx_fragments(
		fragment_length, total_length, memory_region->handle,
		memory_region, recv_buf, memory_region_max_size);

	/* Retrieved all the fragments. */
	ffa_yield();

	/* Point to the whole copied structure. */
	composite = ffa_memory_region_get_composite(memory_region, 0);

	update_mm_security_state(composite, memory_region->attributes);

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;

	for (i = 0; i < PAGE_SIZE; ++i) {
		++ptr[i];
	}

	ffa_yield();
}
/*
 * Secure services fail to share/lend/donate memory to the primary VM.
 */
TEST_SERVICE(invalid_memory_share)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};
	uint32_t msg_size;

	/* If the service partition is not an SP, do not execute. */
	assert(!ffa_is_vm_id(hf_vm_get_id()));

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  send_buf, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  HF_PRIMARY_VM_ID, constituents, 1, 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* All three memory sharing interfaces must fail. */
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);
	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);
	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size), FFA_DENIED);

	ffa_yield();
}

/**
 * Try lend and donate RO memory with the Zero Memory Flag set.
 * This should fail.
 */
TEST_SERVICE(ffa_memory_fail_clear_ro_memory_on_lend_or_donate)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_memory_access receiver;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)0x7200000, .page_count = 1},
	};
	struct ffa_memory_access_impdef impdef_val =
		ffa_memory_access_impdef_init(0, 0);
	uint32_t msg_size;

	/*
	 * Check that FFA_DENIED is returned for lend transaction.
	 */
	ffa_memory_access_init(
		&receiver, service2_info->vm_id, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &impdef_val);

	ffa_memory_region_init(
		(struct ffa_memory_region *)send_buf, HF_MAILBOX_SIZE,
		hf_vm_get_id(), &receiver, 1, sizeof(struct ffa_memory_access),
		constituents, 1, 0, FFA_MEMORY_REGION_FLAG_CLEAR,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size);

	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);

	/*
	 * Check that FFA_DENIED is returned for donate transaction.
	 */
	ffa_memory_access_init(
		&receiver, service2_info->vm_id, FFA_DATA_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &impdef_val);

	ffa_memory_region_init(
		(struct ffa_memory_region *)send_buf, HF_MAILBOX_SIZE,
		hf_vm_get_id(), &receiver, 1, sizeof(struct ffa_memory_access),
		constituents, 1, 0, FFA_MEMORY_REGION_FLAG_CLEAR,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size);

	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);

	ffa_yield();
}

/**
 * Try lend and donate RO memory and then retrieve with the Zero Memory Flag
 * set. This should fail.
 */
TEST_SERVICE(ffa_memory_fail_clear_ro_memory_on_retrieve)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)0x7200000, .page_count = 1},
	};

	/*
	 * Check when FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH flag is set in
	 * retrieve request for RO memory, FFA_DENIED is returned.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, send_buf, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	ffa_yield();
}
