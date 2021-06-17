/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/exception_handler.h"
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t
	pages[FRAGMENTED_SHARE_PAGE_COUNT * PAGE_SIZE];
static uint8_t retrieve_buffer[HF_MAILBOX_SIZE];

/**
 * Helper function to test sending memory in the different configurations.
 */
static void check_cannot_send_memory(
	struct mailbox_buffers mb,
	struct ffa_value (*send_function)(uint32_t, uint32_t),
	struct ffa_memory_region_constituent constituents[],
	int constituent_count, int32_t avoid_vm)

{
	enum ffa_data_access data_access[] = {
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RESERVED};
	enum ffa_instruction_access instruction_access[] = {
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_INSTRUCTION_ACCESS_X, FFA_INSTRUCTION_ACCESS_RESERVED};
	enum ffa_memory_cacheability cacheability[] = {
		FFA_MEMORY_CACHE_RESERVED, FFA_MEMORY_CACHE_NON_CACHEABLE,
		FFA_MEMORY_CACHE_RESERVED_1, FFA_MEMORY_CACHE_WRITE_BACK};
	enum ffa_memory_cacheability device[] = {
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_DEV_NGNRE,
		FFA_MEMORY_DEV_NGRE, FFA_MEMORY_DEV_GRE};
	enum ffa_memory_shareability shareability[] = {
		FFA_MEMORY_SHARE_NON_SHAREABLE, FFA_MEMORY_SHARE_RESERVED,
		FFA_MEMORY_OUTER_SHAREABLE, FFA_MEMORY_INNER_SHAREABLE};
	uint32_t vms[] = {HF_PRIMARY_VM_ID, SERVICE_VM1, SERVICE_VM2};

	size_t i = 0;
	size_t j = 0;
	size_t k = 0;
	size_t l = 0;
	size_t m = 0;

	for (i = 0; i < ARRAY_SIZE(vms); ++i) {
		/* Optionally skip one VM as the send would succeed. */
		if (vms[i] == avoid_vm) {
			continue;
		}
		for (j = 0; j < ARRAY_SIZE(data_access); ++j) {
			for (k = 0; k < ARRAY_SIZE(instruction_access); ++k) {
				for (l = 0; l < ARRAY_SIZE(shareability); ++l) {
					for (m = 0;
					     m < ARRAY_SIZE(cacheability);
					     ++m) {
						uint32_t msg_size;
						EXPECT_EQ(
							ffa_memory_region_init(
								mb.send,
								HF_MAILBOX_SIZE,
								HF_PRIMARY_VM_ID,
								vms[i],
								constituents,
								constituent_count,
								0, 0,
								data_access[j],
								instruction_access
									[k],
								FFA_MEMORY_NORMAL_MEM,
								cacheability[m],
								shareability[l],
								NULL,
								&msg_size),
							0);
						struct ffa_value ret =
							send_function(msg_size,
								      msg_size);

						EXPECT_EQ(ret.func,
							  FFA_ERROR_32);
						EXPECT_TRUE(
							ffa_error_code(ret) ==
								FFA_DENIED ||
							ffa_error_code(ret) ==
								FFA_INVALID_PARAMETERS);
					}
					for (m = 0; m < ARRAY_SIZE(device);
					     ++m) {
						uint32_t msg_size;
						EXPECT_EQ(
							ffa_memory_region_init(
								mb.send,
								HF_MAILBOX_SIZE,
								HF_PRIMARY_VM_ID,
								vms[i],
								constituents,
								constituent_count,
								0, 0,
								data_access[j],
								instruction_access
									[k],
								FFA_MEMORY_DEVICE_MEM,
								device[m],
								shareability[l],
								NULL,
								&msg_size),
							0);
						struct ffa_value ret =
							send_function(msg_size,
								      msg_size);

						EXPECT_EQ(ret.func,
							  FFA_ERROR_32);
						EXPECT_TRUE(
							ffa_error_code(ret) ==
								FFA_DENIED ||
							ffa_error_code(ret) ==
								FFA_INVALID_PARAMETERS);
					}
				}
			}
		}
	}
}

/**
 * Helper function to test lending memory in the different configurations.
 */
static void check_cannot_lend_memory(
	struct mailbox_buffers mb,
	struct ffa_memory_region_constituent constituents[],
	int constituent_count, int32_t avoid_vm)

{
	check_cannot_send_memory(mb, ffa_mem_lend, constituents,
				 constituent_count, avoid_vm);
}

/**
 * Helper function to test sharing memory in the different configurations.
 */
static void check_cannot_share_memory(
	struct mailbox_buffers mb,
	struct ffa_memory_region_constituent constituents[],
	int constituent_count, int32_t avoid_vm)

{
	check_cannot_send_memory(mb, ffa_mem_share, constituents,
				 constituent_count, avoid_vm);
}

/**
 * Tries donating memory in available modes with different VMs and asserts that
 * it will fail to all except the supplied VM ID as this would succeed if it
 * is the only borrower.
 */
static void check_cannot_donate_memory(
	struct mailbox_buffers mb,
	struct ffa_memory_region_constituent constituents[],
	int constituent_count, int32_t avoid_vm)
{
	uint32_t vms[] = {HF_PRIMARY_VM_ID, SERVICE_VM1, SERVICE_VM2};

	size_t i;
	for (i = 0; i < ARRAY_SIZE(vms); ++i) {
		uint32_t msg_size;
		struct ffa_value ret;
		/* Optionally skip one VM as the donate would succeed. */
		if (vms[i] == avoid_vm) {
			continue;
		}
		EXPECT_EQ(ffa_memory_region_init(
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  vms[i], constituents, constituent_count, 0, 0,
				  FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
			  0);
		ret = ffa_mem_donate(msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_TRUE((ffa_error_code(ret) == FFA_DENIED) ||
			    (ffa_error_code(ret) == FFA_INVALID_PARAMETERS));
	}
}

/**
 * Tries relinquishing memory with different VMs and asserts that
 * it will fail.
 */
static void check_cannot_relinquish_memory(struct mailbox_buffers mb,
					   ffa_memory_handle_t handle)
{
	uint32_t vms[] = {HF_PRIMARY_VM_ID, SERVICE_VM1, SERVICE_VM2};

	size_t i;
	for (i = 0; i < ARRAY_SIZE(vms); ++i) {
		struct ffa_mem_relinquish *relinquish_req =
			(struct ffa_mem_relinquish *)mb.send;

		*relinquish_req = (struct ffa_mem_relinquish){
			.handle = handle, .endpoint_count = 1};
		relinquish_req->endpoints[0] = vms[i];
		EXPECT_FFA_ERROR(ffa_mem_relinquish(), FFA_INVALID_PARAMETERS);
	}
}

TEAR_DOWN(memory_sharing)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Sharing memory concurrently gives both VMs access to the memory so it can be
 * used for communication.
 */
TEST(memory_sharing, concurrent)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "memory_increment", mb.send);

	memset_s(ptr, sizeof(pages), 'a', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	for (int i = 0; i < PAGE_SIZE; ++i) {
		pages[i] = i;
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	for (int i = 0; i < PAGE_SIZE; ++i) {
		uint8_t value = i + 1;

		EXPECT_EQ(pages[i], value);
	}
}

/**
 * Memory shared concurrently can be returned to the owner.
 */
TEST(memory_sharing, share_concurrently_and_get_back)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish", mb.send);

	/* Dirty the memory before sharing it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	/* Let the memory be returned. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Device address space cannot be shared, only normal memory.
 */
TEST(memory_sharing, cannot_share_device_memory)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)PAGE_SIZE, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_return", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_return", mb.send);

	check_cannot_lend_memory(mb, constituents, ARRAY_SIZE(constituents),
				 -1);
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  -1);
	check_cannot_donate_memory(mb, constituents, ARRAY_SIZE(constituents),
				   -1);
}

/**
 * Check that memory can be lent and is accessible by both parties.
 */
TEST(memory_sharing, lend_relinquish)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	ffa_memory_handle_t handle;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);

	/* Let the memory be returned. */
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Ensure that the secondary VM accessed the region. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Check that memory can be lent and retrieved with multiple fragments.
 */
TEST(memory_sharing, lend_fragmented_relinquish)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t i;
	ffa_memory_handle_t handle;
	struct ffa_memory_region_constituent
		constituents[FRAGMENTED_SHARE_PAGE_COUNT];

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b',
		 PAGE_SIZE * FRAGMENTED_SHARE_PAGE_COUNT);

	for (i = 0; i < ARRAY_SIZE(constituents); ++i) {
		constituents[i].address = (uint64_t)pages + i * PAGE_SIZE;
		constituents[i].page_count = 1;
		constituents[i].reserved = 0;
	}

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);

	/* Let the memory be returned. */
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Ensure that the secondary VM accessed the region. */
	for (int i = 0; i < PAGE_SIZE * FRAGMENTED_SHARE_PAGE_COUNT; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Check that memory can be lent with multiple fragments even though it could
 * fit in one.
 */
TEST(memory_sharing, lend_force_fragmented_relinquish)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	ffa_memory_handle_t handle;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request_force_fragmented(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);

	/* Let the memory be returned. */
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Ensure that the secondary VM accessed the region. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Check that memory that is donated can't be relinquished.
 */
TEST(memory_sharing, donate_relinquish)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_donate_relinquish", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2},
	};

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	/*
	 * Let the service access the memory, and try and fail to relinquish it.
	 */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Memory given away can be given back.
 */
TEST(memory_sharing, give_and_get_back)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_return", mb.send);

	/* Dirty the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be returned, and retrieve it. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, run_res, NULL,
					       NULL, HF_MAILBOX_SIZE),
		  SERVICE_VM1);

	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Memory that has been lent can be returned to the owner.
 */
TEST(memory_sharing, lend_and_get_back)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish", mb.send);

	/* Dirty the memory before lending it. */
	memset_s(ptr, sizeof(pages), 'c', PAGE_SIZE);

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be returned. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'd');
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * After memory has been returned, it is free to be lent again.
 */
TEST(memory_sharing, relend_after_return)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_relend",
		       mb.send);

	/* Lend the memory initially. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be returned. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(run_res.arg2, 0);
	EXPECT_EQ(run_res.arg3, 0);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Lend the memory again after it has been returned. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Observe the service doesn't fault when accessing the memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(run_res.arg2, 0);
	EXPECT_EQ(run_res.arg3, 0);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}

/**
 * After memory has been returned, it is free to be lent to another VM.
 */
TEST(memory_sharing, lend_elsewhere_after_return)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_lend_relinquish", mb.send);

	/* Lend the memory initially. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be returned. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Share the memory with a different VM after it has been returned. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM2,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * After memory has been given, it is no longer accessible by the sharing VM.
 */
TEST(memory_sharing, give_memory_and_lose_access)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;

	SERVICE_SELECT(SERVICE_VM1, "give_memory_and_fault", mb.send);

	/* Have the memory be given. */
	run_res = ffa_run(SERVICE_VM1, 0);
	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, run_res, NULL,
					       memory_region, HF_MAILBOX_SIZE),
		  SERVICE_VM1);

	/* Check the memory was cleared. */
	ASSERT_EQ(memory_region->receiver_count, 1);
	ASSERT_NE(memory_region->receivers[0].composite_memory_region_offset,
		  0);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	ptr = (uint8_t *)composite->constituents[0].address;
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 0);
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * After memory has been lent, it is no longer accessible by the sharing VM.
 */
TEST(memory_sharing, lend_memory_and_lose_access)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;

	SERVICE_SELECT(SERVICE_VM1, "lend_memory_and_fault", mb.send);

	/* Have the memory be lent. */
	run_res = ffa_run(SERVICE_VM1, 0);
	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, run_res, NULL,
					       memory_region, HF_MAILBOX_SIZE),
		  SERVICE_VM1);

	/* Check the memory was cleared. */
	ASSERT_EQ(memory_region->receiver_count, 1);
	ASSERT_NE(memory_region->receivers[0].composite_memory_region_offset,
		  0);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	ptr = (uint8_t *)composite->constituents[0].address;
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 0);
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Verify past the upper bound of the donated region cannot be accessed.
 */
TEST(memory_sharing, donate_check_upper_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_check_upper_bound", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_check_upper_bound", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', 4 * PAGE_SIZE);

	/* Specify non-contiguous memory regions. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE * 2, .page_count = 1},
	};

	/*
	 * Specify that we want to test the first constituent of the donated
	 * memory region. This is utilised by the test service.
	 */
	pages[0] = 0;

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);

	/* Use different memory regions for verifying the second constituent. */
	constituents[0].address = (uint64_t)pages + PAGE_SIZE * 1;
	constituents[1].address = (uint64_t)pages + PAGE_SIZE * 3;

	/*
	 * Specify that we now want to test the second constituent of the
	 * donated memory region.
	 */
	pages[PAGE_SIZE] = 1;

	/*
	 * Use the second secondary VM for this test as the first is now in an
	 * exception loop.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM2,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Verify past the lower bound of the donated region cannot be accessed.
 */
TEST(memory_sharing, donate_check_lower_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_check_lower_bound", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_check_lower_bound", mb.send);

	/* Initialise the memory before donating it. */
	memset_s(ptr, sizeof(pages), 'b', 4 * PAGE_SIZE);

	/* Specify non-contiguous memory regions. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE * 2, .page_count = 1},
	};

	/*
	 * Specify that we want to test the first constituent of the donated
	 * memory region. This is utilised by the test service.
	 */
	pages[0] = 0;

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);

	/* Use different memory regions for verifying the second constituent. */
	constituents[0].address = (uint64_t)pages + PAGE_SIZE * 1;
	constituents[1].address = (uint64_t)pages + PAGE_SIZE * 3;

	/*
	 * Specify that we now want to test the second constituent of the
	 * donated memory region.
	 */
	pages[PAGE_SIZE] = 1;

	/*
	 * Use the second secondary VM for this test as the first is now in an
	 * exception loop.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM2,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * After memory has been returned, it is free to be shared with another
 * VM.
 */
TEST(memory_sharing, donate_elsewhere_after_return)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_return", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_return", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', 1 * PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);

	/* Let the memory be returned. */
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, run_res, NULL,
					       NULL, HF_MAILBOX_SIZE),
		  SERVICE_VM1);

	/* Share the memory with another VM. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM2,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Check if memory can be donated between secondary VMs.
 * Ensure that the memory can no longer be accessed by the first VM.
 */
TEST(memory_sharing, donate_vms)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_donate_secondary_and_fault", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_receive", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', 1 * PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Set up VM2 to wait for message. */
	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);

	/* Donate memory. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be sent from VM1 to VM2. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_receiver(run_res), SERVICE_VM2);

	/* Receive memory in VM2. */
	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Try to access memory in VM1. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);

	/* Ensure that memory in VM2 remains the same. */
	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Check that memory is unable to be donated to multiple parties.
 */
TEST(memory_sharing, donate_twice)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_donate_twice", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_receive", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', 1 * PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Donate memory to VM1. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be received. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Fail to share memory again with any VM. */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  -1);
	check_cannot_lend_memory(mb, constituents, ARRAY_SIZE(constituents),
				 -1);
	check_cannot_donate_memory(mb, constituents, ARRAY_SIZE(constituents),
				   -1);
	/* Fail to relinquish memory from any VM. */
	check_cannot_relinquish_memory(mb, handle);

	/* Let the memory be sent from VM1 to PRIMARY (returned). */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, run_res, NULL,
					       NULL, HF_MAILBOX_SIZE),
		  SERVICE_VM1);

	/* Check we have access again. */
	ptr[0] = 'f';

	/* Try and fail to donate memory from VM1 to VM2. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Check cannot donate to self.
 */
TEST(memory_sharing, donate_to_self)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  HF_PRIMARY_VM_ID, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);

	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Check cannot lend to self.
 */
TEST(memory_sharing, lend_to_self)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  HF_PRIMARY_VM_ID, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Check cannot share to self.
 */
TEST(memory_sharing, share_to_self)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  HF_PRIMARY_VM_ID, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Check cannot donate from alternative VM.
 */
TEST(memory_sharing, donate_invalid_source)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	SERVICE_SELECT(SERVICE_VM1, "ffa_donate_invalid_source", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_receive", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Try invalid configurations. */
	EXPECT_EQ(
		ffa_memory_region_init(
			mb.send, HF_MAILBOX_SIZE, SERVICE_VM1, HF_PRIMARY_VM_ID,
			constituents, ARRAY_SIZE(constituents), 0, 0,
			FFA_DATA_ACCESS_NOT_SPECIFIED,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, SERVICE_VM1, SERVICE_VM1,
			  constituents, ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, SERVICE_VM2, SERVICE_VM1,
			  constituents, ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);

	/* Successfully donate to VM1. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);

	/* Receive and return memory from VM1. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, run_res, NULL,
					       NULL, HF_MAILBOX_SIZE),
		  SERVICE_VM1);

	/* Use VM1 to fail to donate memory from the primary to VM2. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Check that unaligned addresses can not be shared.
 */
TEST(memory_sharing, give_and_get_back_unaligned)
{
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_return", mb.send);

	/* Check for unaligned pages for either constituent. */
	for (int i = 0; i < PAGE_SIZE; i++) {
		for (int j = 0; i < PAGE_SIZE; i++) {
			/* Skip the case they're both aligned. */
			if (i == 0 && j == 0) {
				continue;
			}
			struct ffa_memory_region_constituent constituents[] = {
				{.address = (uint64_t)pages + i,
				 .page_count = 1},
				{.address = (uint64_t)pages + PAGE_SIZE + j,
				 .page_count = 1},
			};
			uint32_t msg_size;
			EXPECT_EQ(
				ffa_memory_region_init(
					mb.send, HF_MAILBOX_SIZE,
					HF_PRIMARY_VM_ID, SERVICE_VM1,
					constituents, ARRAY_SIZE(constituents),
					0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
					FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
					FFA_MEMORY_NORMAL_MEM,
					FFA_MEMORY_CACHE_WRITE_BACK,
					FFA_MEMORY_INNER_SHAREABLE, NULL,
					&msg_size),
				0);
			EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
					 FFA_INVALID_PARAMETERS);
			EXPECT_EQ(
				ffa_memory_region_init(
					mb.send, HF_MAILBOX_SIZE,
					HF_PRIMARY_VM_ID, SERVICE_VM1,
					constituents, ARRAY_SIZE(constituents),
					0, 0, FFA_DATA_ACCESS_RW,
					FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
					FFA_MEMORY_NORMAL_MEM,
					FFA_MEMORY_CACHE_WRITE_BACK,
					FFA_MEMORY_INNER_SHAREABLE, NULL,
					&msg_size),
				0);
			EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size),
					 FFA_INVALID_PARAMETERS);
		}
	}
}

/**
 * Check cannot lend from alternative VM.
 */
TEST(memory_sharing, lend_invalid_source)
{
	struct ffa_value run_res;
	ffa_memory_handle_t handle;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	SERVICE_SELECT(SERVICE_VM1, "ffa_lend_invalid_source", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Check cannot swap VM IDs. */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, SERVICE_VM1,
			  HF_PRIMARY_VM_ID, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);

	/* Lend memory to VM1. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Receive and return memory from VM1. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Try to lend memory from primary in VM1. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Memory can be lent with executable permissions.
 * Check RO and RW permissions.
 */
TEST(memory_sharing, lend_relinquish_X_RW)
{
	struct ffa_value run_res;
	ffa_memory_handle_t handle;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_RW", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Let service write to and return memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Re-initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Memory cannot be shared with executable permissions.
 * Check RO and RW permissions.
 */
TEST(memory_sharing, share_X_RW)
{
	ffa_memory_handle_t handle;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_value run_res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_share_fail", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the secondary VM fail to retrieve the memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
		ptr[i]++;
	}

	/* Reclaim the memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Re-initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the secondary VM fail to retrieve the memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
		ptr[i]++;
	}

	/* Reclaim the memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}

/**
 * Memory can be shared without executable permissions.
 * Check RO and RW permissions.
 */
TEST(memory_sharing, share_relinquish_NX_RW)
{
	struct ffa_value run_res;
	ffa_memory_handle_t handle;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_RW", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
	}

	/* Let service write to and return memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Re-initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
		ptr[i]++;
	}

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Test that memory which is shared cannot be cleared when it is relinquished.
 */
TEST(memory_sharing, share_relinquish_clear)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	size_t i;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_share_relinquish_clear",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	/* Let the memory be received, fail to be cleared, and then returned. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Check that it has not been cleared. */
	for (i = 0; i < PAGE_SIZE * 2; ++i) {
		ASSERT_EQ(ptr[i], 'b');
	};
}

/**
 * Exercise execution permissions for lending memory.
 */
TEST(memory_sharing, lend_relinquish_RW_X)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_X", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 0, PAGE_SIZE);

	uint64_t *ptr2 = (uint64_t *)pages;
	/* Set memory to contain the RET instruction to attempt to execute. */
	*ptr2 = 0xD65F03C0;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Attempt to execute from memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Exercise execution permissions for lending memory without write access.
 */
TEST(memory_sharing, lend_relinquish_RO_X)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_X", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 0, PAGE_SIZE);

	uint64_t *ptr2 = (uint64_t *)pages;
	/* Set memory to contain the RET instruction to attempt to execute. */
	*ptr2 = 0xD65F03C0;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Attempt to execute from memory. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Memory can be lent, but then no part can be donated.
 */
TEST(memory_sharing, lend_donate)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_RW", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_lend_relinquish_RW", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	/* Lend memory to VM1. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we can't donate any sub section of memory to another VM. */
	constituents[0].page_count = 1;
	for (int i = 1; i < PAGE_SIZE * 2; i++) {
		constituents[0].address = (uint64_t)pages + PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init(
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  SERVICE_VM2, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
				 FFA_DENIED);
	}

	/* Ensure we can't donate to the only borrower. */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);
}

/**
 * Memory can be shared, but then no part can be donated.
 */
TEST(memory_sharing, share_donate)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_relinquish_RW", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_lend_relinquish_RW", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE * 4);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 2, .page_count = 2},
	};

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Attempt to share the same area of memory. */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  SERVICE_VM1);

	/* Ensure we can't donate any sub section of memory to another VM. */
	constituents[0].page_count = 1;
	for (int i = 1; i < PAGE_SIZE * 2; i++) {
		constituents[0].address = (uint64_t)pages + PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init(
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  SERVICE_VM2, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
				 FFA_DENIED);
	}

	/* Ensure we can't donate to the only borrower. */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);
}

/**
 * Memory can be lent, but then no part can be lent again.
 */
TEST(memory_sharing, lend_twice)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_twice", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_lend_twice", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE * 4);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	/* Lend memory to VM1. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Attempt to lend the same area of memory. */
	check_cannot_lend_memory(mb, constituents, ARRAY_SIZE(constituents),
				 -1);
	/* Attempt to share the same area of memory. */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  -1);
	/* Fail to donate to VM apart from VM1. */
	check_cannot_donate_memory(mb, constituents, ARRAY_SIZE(constituents),
				   SERVICE_VM1);
	/* Fail to relinquish from any VM. */
	check_cannot_relinquish_memory(mb, handle);

	/* Now attempt to share only a portion of the same area of memory. */
	struct ffa_memory_region_constituent constituents_subsection[] = {
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	check_cannot_lend_memory(mb, constituents_subsection,
				 ARRAY_SIZE(constituents_subsection), -1);
	check_cannot_donate_memory(mb, constituents_subsection,
				   ARRAY_SIZE(constituents_subsection),
				   SERVICE_VM1);

	/* Attempt to lend again with different permissions. */
	constituents[0].page_count = 1;
	for (int i = 0; i < 2; i++) {
		constituents[0].address = (uint64_t)pages + i * PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init(
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  SERVICE_VM2, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RO,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);
	}
}

/**
 * Memory can be shared, but then no part can be shared again.
 */
TEST(memory_sharing, share_twice)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_lend_twice", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_memory_lend_twice", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NX);

	/* Let the memory be accessed. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/*
	 * Attempting to share or lend the same area of memory with any VM
	 * should fail.
	 */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  -1);
	check_cannot_lend_memory(mb, constituents, ARRAY_SIZE(constituents),
				 -1);
	/* Fail to donate to VM apart from VM1. */
	check_cannot_donate_memory(mb, constituents, ARRAY_SIZE(constituents),
				   SERVICE_VM1);
	/* Fail to relinquish from any VM. */
	check_cannot_relinquish_memory(mb, handle);

	/* Attempt to share again with different permissions. */
	constituents[0].page_count = 1;
	for (int i = 0; i < 2; i++) {
		constituents[0].address = (uint64_t)pages + i * PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init(
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  SERVICE_VM2, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RO,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size), FFA_DENIED);
	}
}

/**
 * Memory can be cleared while being lent.
 */
TEST(memory_sharing, lend_clear)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	ffa_memory_handle_t handle;
	size_t i;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_return", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	/* Lend memory with clear flag. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents),
		FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);
	/* Take it back again. */
	ffa_mem_reclaim(handle, 0);

	/* Check that it has not been cleared. */
	for (i = 0; i < PAGE_SIZE * 2; ++i) {
		ASSERT_EQ(ptr[i], 0);
	};
}

/**
 * Memory cannot be cleared while being shared.
 */
TEST(memory_sharing, share_clear)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;
	size_t i;

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_return", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RO,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);

	/* Check that it has not been cleared. */
	for (i = 0; i < PAGE_SIZE * 2; ++i) {
		ASSERT_EQ(ptr[i], 'b');
	};
}

/**
 * FF-A: Verify past the upper bound of the lent region cannot be accessed.
 */
TEST(memory_sharing, ffa_lend_check_upper_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_check_upper_bound", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_check_upper_bound", mb.send);

	/* Initialise the memory before lending it. */
	memset_s(ptr, sizeof(pages), 'b', 4 * PAGE_SIZE);

	/* Specify non-contiguous memory regions. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE * 2, .page_count = 1},
	};

	/*
	 * Specify that we want to test the first constituent of the donated
	 * memory region. This is utilised by the test service.
	 */
	pages[0] = 0;

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);

	/* Use different memory regions for verifying the second constituent. */
	constituents[0].address = (uint64_t)pages + PAGE_SIZE * 1;
	constituents[1].address = (uint64_t)pages + PAGE_SIZE * 3;

	/*
	 * Specify that we now want to test the second constituent of the
	 * lent memory region.
	 */
	pages[PAGE_SIZE] = 1;

	/*
	 * Use the second secondary VM for this test as the first is now in an
	 * exception loop.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM2,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * FF-A: Verify past the lower bound of the lent region cannot be accessed.
 */
TEST(memory_sharing, ffa_lend_check_lower_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;

	SERVICE_SELECT(SERVICE_VM1, "ffa_check_lower_bound", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "ffa_check_lower_bound", mb.send);

	/* Initialise the memory before lending it. */
	memset_s(ptr, sizeof(pages), 'b', 4 * PAGE_SIZE);

	/* Specify non-contiguous memory regions. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE * 2, .page_count = 1},
	};

	/*
	 * Specify that we want to test the first constituent of the lent
	 * memory region. This is utilised by the test service.
	 */
	pages[0] = 0;

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM1,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);

	/* Use different memory regions for verifying the second constituent. */
	constituents[0].address = (uint64_t)pages + PAGE_SIZE * 1;
	constituents[1].address = (uint64_t)pages + PAGE_SIZE * 3;

	/*
	 * Specify that we now want to test the second constituent of the
	 * lent memory region.
	 */
	pages[PAGE_SIZE] = 1;

	/*
	 * Use the second secondary VM for this test as the first is now in an
	 * exception loop.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, HF_PRIMARY_VM_ID, SERVICE_VM2,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Memory can't be shared if flags in the memory transaction description that
 * Must Be Zero, are not.
 */
TEST(memory_sharing, ffa_validate_mbz)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;

	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
		ffa_mem_donate,
	};

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	/* Prepare memory region, and set all flags */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, 0xffffffff, FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);

	/* Using the same region, call the various mem send functions. */
	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);
	}
}

/**
 * Memory can't be shared if flags in the memory transaction description that
 * Must Be Zero, are not.
 */
TEST(memory_sharing, ffa_validate_retrieve_req_mbz)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;

	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
	};

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_share_fail_invalid_parameters",
		       mb.send);

	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		/* Prepare memory region, and set all flags */
		EXPECT_EQ(ffa_memory_region_init(
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
				  SERVICE_VM1, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RW,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
			  0);

		ret = send_function[0](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);

		handle = ffa_mem_success_handle(ret);

		msg_size = ffa_memory_retrieve_request_init(
			mb.send, handle, HF_PRIMARY_VM_ID, SERVICE_VM1, 0,
			0xFFFFFFFF, FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE);

		EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

		EXPECT_EQ(
			ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size, 0)
				.func,
			FFA_SUCCESS_32);

		ffa_run(SERVICE_VM1, 0);

		EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	}
}

/**
 * If memory is shared can't request zeroing of memory at both send and
 * relinquish.
 */
TEST(memory_sharing, ffa_validate_retrieve_req_clear_flag_if_mem_share)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_share_fail_invalid_parameters",
		       mb.send);

	/* If mem share can't clear memory before sharing. */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);

	/*
	 * Same should happen when using FFA_MEM_RETRIEVE interface.
	 * Attempt to successfully share, and validate error return in the
	 * receiver.
	 */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	handle = ffa_mem_success_handle(ret);

	/* Prepare retrieve request setting clear memory flags. */
	msg_size = ffa_memory_retrieve_request_init(
		mb.send, handle, HF_PRIMARY_VM_ID, SERVICE_VM1, 0,
		FFA_MEMORY_REGION_FLAG_CLEAR |
			FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	EXPECT_EQ(ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size, 0).func,
		  FFA_SUCCESS_32);

	ffa_run(SERVICE_VM1, 0);

	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}

/**
 * If memory is lent with RO permissions, receiver can't request zeroing of
 * memory at relinquish.
 */
TEST(memory_sharing, ffa_validate_retrieve_req_clear_flag_if_RO)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(SERVICE_VM1, "ffa_memory_share_fail", mb.send);

	/* Call FFA_MEM_SEND, setting FFA_DATA_ACCESS_RO. */
	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  SERVICE_VM1, constituents, ARRAY_SIZE(constituents),
			  0, 0, FFA_DATA_ACCESS_RO,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size),
		  0);

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	handle = ffa_mem_success_handle(ret);

	/*
	 * Prepare retrieve request with RO, and setting flag to clear memory.
	 * Should fail at the receiver's FFA_MEM_RETRIEVE call.
	 */
	msg_size = ffa_memory_retrieve_request_init(
		mb.send, handle, HF_PRIMARY_VM_ID, SERVICE_VM1, 0,
		FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	EXPECT_EQ(ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size, 0).func,
		  FFA_SUCCESS_32);

	ffa_run(SERVICE_VM1, 0);

	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}
