/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa.h"
#include "hf/ffa_v1_0.h"
#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t
	pages[FRAGMENTED_SHARE_PAGE_COUNT * PAGE_SIZE];
static uint8_t retrieve_buffer[HF_MAILBOX_SIZE];
static struct ffa_memory_region_constituent
	constituents_lend_fragmented_relinquish[FRAGMENTED_SHARE_PAGE_COUNT];

/**
 * Helper function to test sending memory in the different configurations.
 */
static void check_cannot_send_memory(
	struct mailbox_buffers mb,
	struct ffa_value (*send_function)(uint32_t, uint32_t),
	struct ffa_memory_region_constituent constituents[],
	int constituent_count, uint32_t avoid_vm)
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	uint32_t vms[] = {hf_vm_get_id(), service1_info->vm_id,
			  service2_info->vm_id};

	size_t i = 0;
	size_t j = 0;
	size_t k = 0;
	size_t l = 0;
	size_t m = 0;

	for (i = 0; i < ARRAY_SIZE(vms); ++i) {
		struct ffa_memory_access_impdef impdef_val =
			ffa_memory_access_impdef_init(vms[i], vms[i] + 1);
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
							ffa_memory_region_init_single_receiver(
								mb.send,
								HF_MAILBOX_SIZE,
								hf_vm_get_id(),
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
								&impdef_val,
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
							ffa_memory_region_init_single_receiver(
								mb.send,
								HF_MAILBOX_SIZE,
								hf_vm_get_id(),
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
								&impdef_val,
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
	int constituent_count, uint32_t avoid_vm)
{
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	uint32_t vms[] = {hf_vm_get_id(), service1_info->vm_id,
			  service2_info->vm_id};

	size_t i;
	for (i = 0; i < ARRAY_SIZE(vms); ++i) {
		uint32_t msg_size;
		struct ffa_value ret;
		/* Optionally skip one VM as the donate would succeed. */
		if (vms[i] == avoid_vm) {
			continue;
		}
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  vms[i], constituents, constituent_count, 0, 0,
				  FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	uint32_t vms[] = {hf_vm_get_id(), service1_info->vm_id,
			  service2_info->vm_id};

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

/**
 * Base test function for a memory reclaim after a successful memory send call.
 */
static void memory_send_reclaim(uint32_t msg_size,
				struct ffa_value (*mem_send_function)(uint32_t,
								      uint32_t))
{
	struct ffa_value ret;
	ffa_memory_handle_t handle;

	/*
	 * It is assumed that the same pages as for other mem share tests are
	 * used.
	 */
	uint8_t *ptr = pages;
	ret = mem_send_function(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	handle = ffa_mem_success_handle(ret);

	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Write to pages to validate access has been reestablished. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		ptr[i] = i;
	}
}

/*
 * Test function to lend memory, have the receiver retrieve and relinquish it,
 * reclaim the memory, then check the contents of the memory is either
 * incremented or zeroed.
 */
static void lend_and_check_memory_increment(
	struct mailbox_buffers *mb,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count,
	struct ffa_memory_access receivers_send_permissions[],
	struct ffa_memory_access receivers_retrieve_permissions[],
	uint32_t receivers_count, enum ffa_memory_type send_memory_type,
	enum ffa_memory_type receive_memory_type,
	enum ffa_memory_cacheability memory_cacheability,
	uint32_t number_of_retrieves, bool zero_memory_after_relinquish,
	bool expect_zeroed)
{
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	struct ffa_memory_region *mem_region =
		(struct ffa_memory_region *)mb->send;
	uint32_t msg_size;
	uint8_t *ptr = pages;

	ffa_memory_region_init(mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(),
			       receivers_send_permissions, receivers_count,
			       sizeof(struct ffa_memory_access), constituents,
			       constituent_count, 0, 0, send_memory_type,
			       memory_cacheability, FFA_MEMORY_INNER_SHAREABLE,
			       NULL, &msg_size);

	for (uint32_t i = 0; i < PAGE_SIZE; ++i) {
		ptr[i] = i;
	}

	ret = ffa_mem_lend(msg_size, msg_size);

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	for (uint32_t j = 0; j < number_of_retrieves; j++) {
		for (uint32_t k = 0; k < receivers_count; k++) {
			ffa_id_t recipient =
				receivers_retrieve_permissions[k]
					.receiver_permissions.receiver;
			struct ffa_partition_msg *retrieve_message = mb->send;

			/* Set flag to clear memory after relinquish. */
			msg_size = ffa_memory_retrieve_request_init(
				(struct ffa_memory_region *)
					retrieve_message->payload,
				handle, hf_vm_get_id(),
				receivers_retrieve_permissions, receivers_count,
				sizeof(struct ffa_memory_access), 0,
				FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND |
					(zero_memory_after_relinquish &
					 FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH),
				receive_memory_type, memory_cacheability,
				FFA_MEMORY_INNER_SHAREABLE);
			EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

			/*
			 * Send the appropriate retrieve request to the VM so
			 * that it can use it to retrieve the memory.
			 */
			ffa_rxtx_header_init(hf_vm_get_id(), recipient,
					     msg_size,
					     &retrieve_message->header);
			EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
			/* Run borrower such that it can retrieve memory. */
			EXPECT_EQ(ffa_run(recipient, 0).func, FFA_YIELD_32);
		}

		for (uint32_t k = 0; k < receivers_count; k++) {
			ffa_id_t recipient =
				receivers_retrieve_permissions[k]
					.receiver_permissions.receiver;
			/* Run borrower such that it can write to memory. */
			EXPECT_EQ(ffa_run(recipient, 0).func, FFA_YIELD_32);
			/* Run borrower such that it relinquishes its access. */
			EXPECT_EQ(ffa_run(recipient, 0).func, FFA_YIELD_32);
		}
	}

	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Check memory is cleared. */
	for (uint32_t i = 1; i < PAGE_SIZE; ++i) {
		if (expect_zeroed) {
			EXPECT_EQ(ptr[i], 0);
		} else {
			/* Should have been incremented by each receiver. */
			uint8_t value =
				i + number_of_retrieves * receivers_count;
			EXPECT_EQ(ptr[i], value);
		}
	}
}

/*
 * Test service "ffa_memory_return" expects to receive the ID of the partition
 * to send the memory to next.
 */
void send_target_id(ffa_id_t receiver, ffa_id_t target, void *send)
{
	struct ffa_value ret;

	/*
	 * Send the ID `target` to `receiver`, such that it can then relay
	 * memory to it.
	 */
	ret = send_indirect_message(hf_vm_get_id(), receiver, send, &target,
				    sizeof(target), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(receiver, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

SET_UP(memory_sharing)
{
	ASSERT_EQ(ffa_version(FFA_VERSION_COMPILED), FFA_VERSION_COMPILED);
}

SET_UP(memory_sharing_v1_0)
{
	ASSERT_EQ(ffa_version(FFA_VERSION_1_0), FFA_VERSION_COMPILED);
}

SET_UP(memory_sharing_v1_1)
{
	ASSERT_EQ(ffa_version(FFA_VERSION_1_1), FFA_VERSION_COMPILED);
}

/**
 * Test memory reclaim after a donate.
 */
TEST(memory_sharing, donate_reclaim)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Call base function's test. */
	memory_send_reclaim(msg_size, ffa_mem_donate);
}

/**
 * Test memory reclaim after a lend.
 */
TEST(memory_sharing, lend_reclaim)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Call base function's test. */
	memory_send_reclaim(msg_size, ffa_mem_lend);
}

/**
 * Test memory reclaim after a share.
 */
TEST(memory_sharing, share_reclaim)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Call base function's test. */
	memory_send_reclaim(msg_size, ffa_mem_share);
}

/**
 * Perform memory share operation, and propagate retrieve request to the
 * receiver that doesn't specify the memory type. Hafnium should skip its
 * internal validation, and provide the right memory attributes in the
 * FFA_MEM_RETRIEVE_RESP. The receiver will validate the arguments are as
 * expected.
 */
TEST(memory_sharing, share_retrieve_memory_type_not_specified)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "memory_increment_check_mem_attr",
		       mb.send);

	memset_s(ptr, sizeof(pages), 'a', PAGE_SIZE);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Call base function's test. */
	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	/*
	 * Send the appropriate retrieve request to the VM so that it can use it
	 * to retrieve the memory.
	 * The retrieve request doesn't specify the memory type.
	 */
	send_retrieve_request_single_receiver(
		mb.send, handle, hf_vm_get_id(), service1_info->vm_id, 0, 0,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_MEMORY_NOT_SPECIFIED_MEM, 0, 0, NULL);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		EXPECT_EQ(pages[i], 'b');
	}
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "memory_increment", mb.send);

	memset_s(ptr, sizeof(pages), 'a', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		pages[i] = i;
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Dirty the memory before sharing it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	/* Specify the transaction type in the retrieve request. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be returned. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_return", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_return", mb.send);

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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);

	/* Let the memory be returned. */
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	/* Ensure that the secondary VM accessed the region. */
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b',
		 PAGE_SIZE * FRAGMENTED_SHARE_PAGE_COUNT);

	for (i = 0; i < ARRAY_SIZE(constituents_lend_fragmented_relinquish);
	     ++i) {
		constituents_lend_fragmented_relinquish[i].address =
			(uint64_t)pages + i * PAGE_SIZE;
		constituents_lend_fragmented_relinquish[i].page_count = 1;
		constituents_lend_fragmented_relinquish[i].reserved = 0;
	}

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents_lend_fragmented_relinquish,
		ARRAY_SIZE(constituents_lend_fragmented_relinquish), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);

	/* Let the memory be returned. */
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Ensure that the secondary VM accessed the region. */
	for (size_t i = 0; i < PAGE_SIZE * FRAGMENTED_SHARE_PAGE_COUNT; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request_force_fragmented(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X);

	run_res = ffa_run(service1_info->vm_id, 0);
	/* Let the memory be returned. */
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	/* Ensure that the secondary VM accessed the region. */
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Check that memory that is donated can't be relinquished.
 */
TEST(memory_sharing, donate_relinquish)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_donate_relinquish",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
		{.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2},
	};

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/*
	 * Let the service access the memory, and try and fail to relinquish it.
	 */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Memory given away can be given back.
 * Added precondition to this test, for it run on the NWd only, and not on setup
 * with PVM and SP. Because the FF-A specification doesn't permit donate memory
 * from SP to VM.
 */
TEST_PRECONDITION(memory_sharing, give_and_get_back, hypervisor_only)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_return", mb.send);

	send_target_id(service1_info->vm_id, hf_vm_get_id(), mb.send);

	/* Dirty the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	/* Specify the transaction type in the retrieve request. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_DONATE,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be returned, and retrieve it. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, NULL, NULL,
					       HF_MAILBOX_SIZE),
		  service1_info->vm_id);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'c');
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Dirty the memory before lending it. */
	memset_s(ptr, sizeof(pages), 'c', PAGE_SIZE);

	/* Specify the transaction type in the retrieve request. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND, FFA_DATA_ACCESS_RW,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be returned. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'd');
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_lend_relinquish_relend", mb.send);

	/* Lend the memory initially. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be returned. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Lend the memory again after it has been returned. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Observe the service doesn't fault when accessing the memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Lend the memory initially. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be returned. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Share the memory with a different VM after it has been returned. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * After memory has been given, it is no longer accessible by the sharing VM.
 */
TEST_PRECONDITION(memory_sharing, give_memory_and_lose_access, service1_is_vm)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_memory_access *receiver;

	SERVICE_SELECT(service1_info->vm_id, "give_memory_and_fault", mb.send);

	/* Have the memory be given. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, NULL,
					       memory_region, HF_MAILBOX_SIZE),
		  service1_info->vm_id);

	receiver = ffa_memory_region_get_receiver(memory_region, 0);

	/* Check the memory was cleared. */
	ASSERT_EQ(memory_region->receiver_count, 1);
	ASSERT_TRUE(receiver != NULL);
	ASSERT_NE(receiver->composite_memory_region_offset, 0);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 0);
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * After memory has been lent, it is no longer accessible by the sharing VM.
 */
TEST_PRECONDITION(memory_sharing, lend_memory_and_lose_access, service1_is_vm)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint8_t *ptr;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_memory_access *receiver;

	SERVICE_SELECT(service1_info->vm_id, "lend_memory_and_fault", mb.send);

	/* Have the memory be lent. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	memory_region = (struct ffa_memory_region *)retrieve_buffer;
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, NULL,
					       memory_region, HF_MAILBOX_SIZE),
		  service1_info->vm_id);

	receiver = ffa_memory_region_get_receiver(memory_region, 0);

	/* Check the memory was cleared. */
	ASSERT_EQ(memory_region->receiver_count, 1);
	ASSERT_TRUE(receiver != NULL);
	ASSERT_NE(receiver->composite_memory_region_offset, 0);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 0);
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Verify past the upper bound of the donated region cannot be accessed.
 */
TEST(memory_sharing, donate_check_upper_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_check_upper_bound", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_check_upper_bound", mb.send);

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
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

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
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service2_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Verify past the lower bound of the donated region cannot be accessed.
 */
TEST(memory_sharing, donate_check_lower_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_check_lower_bound", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_check_lower_bound", mb.send);

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
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

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
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service2_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * After memory has been returned, it is free to be shared with another
 * partition.
 */
TEST(memory_sharing, donate_and_donate_elsewhere)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_return", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	send_target_id(service1_info->vm_id, service2_info->vm_id, mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', 1 * PAGE_SIZE);

	/* Donate memory to service 1. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/*
	 * Run service1 such it can retrieve memory, and donate it to
	 * service2.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Run service2 for it to retrieve memory donated by service1. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/*
	 * Re-run service1 for it to attempt to access the memory.
	 * Expect exception due to page fault, as the memory is accessible
	 * to service1 anymore.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&ret, mb.recv));
}

/**
 * Check if memory can be donated between secondary VMs.
 * Ensure that the memory can no longer be accessed by the first VM.
 */
TEST(memory_sharing, donate_vms)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_donate_secondary_and_fault",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	/* Let the memory be sent from service1 to service2. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Receive memory in service2. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Try to access memory in service1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

	/* Ensure that memory in service2 remains the same. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Test that once device memory has been lent it is not longer accessible to
 * the original owner.
 */
TEST_PRECONDITION(memory_sharing, lend_device_memory_and_lose_access,
		  service1_and_service2_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_lend_device_memory_secondary_and_fault", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	/* Let the memory be sent from service1 to service2. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Receive memory in service2. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Try to access memory in service1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

	/* Ensure that memory in service2 remains the same. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Test that normal memory can be lent as device memory and that once the memory
 * has been lent it is no longer accessible to the original owner.
 */
TEST_PRECONDITION(memory_sharing, lend_normal_memory_as_device_and_lose_access,
		  service1_and_service2_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&pages, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_lend_normal_memory_as_device_secondary_and_fault",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	/* Lend normal memory to Service2 SP and retrieve as device memory. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_DEV_NGNRNE);

	/* Ensure that memory in service2 remains the same. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Run the same test for SP->SP memory lend. */
	/* Let the memory be sent from service1 to service2. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Receive memory in service2. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Try to access memory in service1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

	/* Ensure that memory in service2 remains the same. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Test that normal memory lent with the device memory type cannot
 * be retrieved with the normal memory type as this breaks precedence rules.
 */
TEST(memory_sharing, lend_normal_as_device_to_multiple)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_access receivers[2];
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef impdef_val =
		ffa_memory_access_impdef_init(0, 0);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &impdef_val);

	/*
	 * Lend the memory as device memory and set the memory type in the
	 * retrieve request to normal memory. This should fail.
	 */
	send_memory_and_retrieve_request_multi_receiver(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), constituents,
		ARRAY_SIZE(constituents), receivers, ARRAY_SIZE(receivers),
		receivers, ARRAY_SIZE(receivers), 0, 0, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_DEV_NGNRNE,
		FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Test that device memory can be shared from one SP to another and both can
 * access it whilst they share it.
 * The device memory shared is UART1 MMIO address space so the output can be
 * viewed in the logs.
 */
TEST_PRECONDITION(memory_sharing, lend_device_memory_between_sps_and_reclaim,
		  service1_and_service2_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_lend_device_memory_to_sp_and_reclaim", mb.send);
	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_memory_lend_relinquish_device", mb.send);

	/* Let the memory be sent from service1 to service2. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Receive memory, access it and relinquish it in service2. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Reclaim in service1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Check the service2 can no longer access the memory it was lent. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Test device memory can be lent from NWd to an endpoint.
 * Then test that once the service has relinquished ownership it can no longer
 * access the memory. This device memory shared is UART2.
 */
TEST(memory_sharing, lend_device_memory_to_sp_and_reclaim)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	/* Lend the UART2 device region. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)0x1c0b0000, .page_count = 1},
	};
	ffa_memory_handle_t handle;
	volatile uint8_t *ptr;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_lend_relinquish_device", mb.send);

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)constituents[0].address;

	/* Try to write to the memory before sharing. */
	*ptr = 'h';
	*ptr = 'e';
	*ptr = 'l';
	*ptr = 'l';
	*ptr = 'o';
	*ptr = '\n';

	/* Lend memory to the next VM. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_DEV_NGNRNE);

	/* Receive memory, access it and relinquish it in service1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	ASSERT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	*ptr = 'h';
	*ptr = 'i';
	*ptr = '\n';

	/*
	 * Check service1 can no longer access the memory it was lent and
	 * relinquished.
	 */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/*
 * Check that memory lent as device memory is maintained during the lend
 * and reliquish operations. The memory is set by the owner, lent, incremented
 * by the borrower and relinquish. The expected values are checked when
 * the owner regains access to the memory.
 */
TEST(memory_sharing, mem_lend_relinquish_reclaim_normal_memory_as_device)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_access receiver_send_permissions;
	struct ffa_memory_access receiver_retrieve_permissions;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	/* Lend the UART2 device region. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&pages, .page_count = 1},
	};
	struct ffa_memory_access_impdef impdef_val =
		ffa_memory_access_impdef_init(0, 0);

	SERVICE_SELECT(service1_info->vm_id, "memory_increment_relinquish",
		       mb.send);

	ffa_memory_access_init(&receiver_send_permissions, service1_info->vm_id,
			       FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef_val);
	ffa_memory_access_init(&receiver_retrieve_permissions,
			       service1_info->vm_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NX, 0, &impdef_val);

	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents),
		&receiver_send_permissions, &receiver_retrieve_permissions, 1,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, 1, false, false);
}

/**
 * Check that memory lent as device memory is zeroed when the Zero memory
 * flag is set during relinquish.
 */
TEST(memory_sharing, mem_lend_zero_memory_after_relinquish_device_memory)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_access receiver_send_permissions;
	struct ffa_memory_access receiver_retrieve_permissions;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&pages, .page_count = 1},
	};
	struct ffa_memory_access_impdef impdef_val =
		ffa_memory_access_impdef_init(0, 0);

	SERVICE_SELECT(
		service1_info->vm_id,
		"memory_increment_relinquish_with_clear_check_not_zeroed",
		mb.send);

	ffa_memory_access_init(&receiver_send_permissions, service1_info->vm_id,
			       FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef_val);
	ffa_memory_access_init(&receiver_retrieve_permissions,
			       service1_info->vm_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NX, 0, &impdef_val);

	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents),
		&receiver_send_permissions, &receiver_retrieve_permissions, 1,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, 1, false, true);

	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents),
		&receiver_send_permissions, &receiver_retrieve_permissions, 1,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_DEVICE_MEM,
		FFA_MEMORY_DEV_NGNRNE, 1, true, true);
}

/**
 * Validate that lent device memory cannot be retrieve as normal memory as this
 * breaks the memory type precedence rules given in section 1.10.4 of the
 * FF-A Memory Management Protocol v1.2 ALP0 document. */
TEST_PRECONDITION(memory_sharing, lend_device_memory_as_normal_fails,
		  service1_and_service2_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	/* Lend the UART2 device region. */
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)0x1c0b0000, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_lend_device_memory_to_sp_as_normal", mb.send);

	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);

	/*
	 * Lend device memory to next VM with the memory type in the retrieve
	 * request set to Normal memory. This should fail.
	 */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_DEV_NGNRNE, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/*
	 * Run the same test for SP->SP memory send.
	 * First run service1 so it lends memory and sends retrieve request to
	 * service2.
	 */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Run service2 to try retrieve the memory, this should fail. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Validate that an SP can't share/donate device memory or lend device memory
 * to multiple borrowers. Currently only lending to a single borrower is
 * supported, and tested so we want to ensure other cases are not permitted.
 */
TEST_PRECONDITION(memory_sharing, invalid_device_share_fails,
		  service1_service2_and_service3_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_lend_device_memory_fails",
		       mb.send);

	/* Run SP to attempt to donate memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Check that memory is unable to be donated to multiple parties.
 */
TEST(memory_sharing, donate_twice)
{
	ffa_memory_handle_t handle;
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_donate_twice", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	send_target_id(service1_info->vm_id, service2_info->vm_id, mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', 1 * PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Donate memory to VM1. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be received. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Fail to share memory again with any VM. */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  -1);
	check_cannot_lend_memory(mb, constituents, ARRAY_SIZE(constituents),
				 -1);
	check_cannot_donate_memory(mb, constituents, ARRAY_SIZE(constituents),
				   -1);
	/* Fail to relinquish memory from any VM. */
	check_cannot_relinquish_memory(mb, handle);

	/* Let the memory be sent from service1 to service2. */
	ret = ffa_run(service1_info->vm_id, 0);
	ASSERT_NE(ret.func, FFA_ERROR_32);

	/* Let service2 retrieve the pending memory. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Try and fail to donate memory from VM1 to VM2. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * Check cannot donate to self.
 */
TEST_PRECONDITION(memory_sharing, donate_to_self, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	EXPECT_EQ(
		ffa_memory_region_init_single_receiver(
			mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			hf_vm_get_id(), constituents, ARRAY_SIZE(constituents),
			0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			FFA_MEMORY_NOT_SPECIFIED_MEM,
			FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
			NULL, NULL, &msg_size),
		0);

	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Check cannot lend to self.
 */
TEST_PRECONDITION(memory_sharing, lend_to_self, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  hf_vm_get_id(), constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Check cannot share to self.
 */
TEST_PRECONDITION(memory_sharing, share_to_self, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  hf_vm_get_id(), constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Check cannot donate from alternative VM.
 */
TEST_PRECONDITION(memory_sharing, donate_invalid_source, hypervisor_only)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_donate_invalid_source",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Try invalid configurations. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, service1_info->vm_id,
			  service2_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, service1_info->vm_id,
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, service2_info->vm_id,
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size), FFA_DENIED);

	/* Successfully donate to VM1. */
	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, mb.send, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Receive and return memory from VM1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	ASSERT_NE(run_res.func, FFA_ERROR_32);
	EXPECT_EQ(retrieve_memory_from_message(mb.recv, mb.send, NULL, NULL,
					       HF_MAILBOX_SIZE),
		  service1_info->vm_id);

	/* Use VM1 to fail to donate memory from the primary to VM2. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Check that unaligned addresses can not be shared.
 */
TEST_PRECONDITION(memory_sharing, give_and_get_back_unaligned, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_return", mb.send);

	/* Check for unaligned pages for either constituent. */
	for (size_t i = 0; i < PAGE_SIZE; i++) {
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
				ffa_memory_region_init_single_receiver(
					mb.send, HF_MAILBOX_SIZE,
					hf_vm_get_id(), service1_info->vm_id,
					constituents, ARRAY_SIZE(constituents),
					0, 0, FFA_DATA_ACCESS_NOT_SPECIFIED,
					FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
					FFA_MEMORY_NOT_SPECIFIED_MEM,
					FFA_MEMORY_CACHE_WRITE_BACK,
					FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
					&msg_size),
				0);
			EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
					 FFA_INVALID_PARAMETERS);
			EXPECT_EQ(
				ffa_memory_region_init_single_receiver(
					mb.send, HF_MAILBOX_SIZE,
					hf_vm_get_id(), service1_info->vm_id,
					constituents, ARRAY_SIZE(constituents),
					0, 0, FFA_DATA_ACCESS_RW,
					FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
					FFA_MEMORY_NOT_SPECIFIED_MEM,
					FFA_MEMORY_CACHE_WRITE_BACK,
					FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_lend_invalid_source",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Check use of invalid partition IDs. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, service1_info->vm_id,
			  service2_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	EXPECT_FFA_ERROR(ffa_mem_lend(msg_size, msg_size), FFA_DENIED);

	/* Lend memory to VM1. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Receive and return memory from VM1. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Try to lend memory from primary in VM1. */
	run_res = ffa_run(service1_info->vm_id, 0);
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish_RW",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Let service write to and return memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Re-initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Memory cannot be shared with executable permissions.
 * Check RO and RW permissions.
 */
TEST(memory_sharing, share_X)
{
	ffa_memory_handle_t handle;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_value run_res;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the secondary VM fail to retrieve the memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
		ptr[i]++;
	}

	/* Reclaim the memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Re-initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the secondary VM fail to retrieve the memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
		ptr[i]++;
	}

	/* Reclaim the memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}

/**
 * Memory should be shared without executable permissions.
 * Check RO and RW permissions.
 */
TEST(memory_sharing, share_relinquish_NX_RW)
{
	struct ffa_value run_res;
	ffa_memory_handle_t handle;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish_RW",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
	}

	/* Let service write to and return memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Re-initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we still have access. */
	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		ASSERT_EQ(ptr[i], 'b');
		ptr[i]++;
	}

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_relinquish_clear", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be received, fail to be cleared, and then returned. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Check that it has not been cleared. */
	for (i = 0; i < PAGE_SIZE * 2; ++i) {
		ASSERT_EQ(ptr[i], 'b');
	};
}

/**
 * Exercise execution permissions for lending memory.
 */
TEST_PRECONDITION(memory_sharing, lend_relinquish_RW_X, service1_is_vm)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish_X",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 0, PAGE_SIZE);

	uint32_t *ptr2 = (uint32_t *)pages;
	/* Set memory to contain the BTI+RET instruction to attempt to execute.
	 */
	*ptr2 = 0xD50324DF; /* BTI jc */
	ptr2++;
	*ptr2 = 0xD65F03C0;
	;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Attempt to execute from memory. */
	run_res = ffa_run(service1_info->vm_id, 0);

	if (run_res.func == FFA_YIELD_32) {
		/* Service running at EL1 */
		EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

		send_memory_and_retrieve_request(
			FFA_MEM_LEND_32, mb.send, hf_vm_get_id(),
			service1_info->vm_id, constituents,
			ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			FFA_INSTRUCTION_ACCESS_NX, FFA_MEMORY_NOT_SPECIFIED_MEM,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_CACHE_WRITE_BACK);

		run_res = ffa_run(service1_info->vm_id, 0);
		EXPECT_TRUE(exception_received(&run_res, mb.recv));
	} else {
		/* Service running at EL0 where SCTLR_EL2.WXN is set. */
		EXPECT_FFA_ERROR(run_res, FFA_ABORTED);
	}
}

/**
 * Exercise execution permissions for lending memory without write access.
 */
TEST_PRECONDITION(memory_sharing, lend_relinquish_RO_X, service1_is_vm)
{
	ffa_memory_handle_t handle;
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish_X",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 0, PAGE_SIZE);

	uint32_t *ptr2 = (uint32_t *)pages;
	/* Set memory to contain the BTI+RET instructions to attempt to execute.
	 */
	*ptr2 = 0xD50324DF; /* BTI jc */
	ptr2++;
	*ptr2 = 0xD65F03C0;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Attempt to execute from memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish_RW",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_lend_relinquish_RW",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	/* Lend memory to VM1. */
	send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Ensure we can't donate any sub section of memory to another VM. */
	constituents[0].page_count = 1;
	for (size_t i = 1; i < PAGE_SIZE * 2; i++) {
		constituents[0].address = (uint64_t)pages + PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service2_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
				 FFA_DENIED);
	}

	/* Ensure we can't donate to the only borrower. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_relinquish_RW",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_lend_relinquish_RW",
		       mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE * 4);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 2, .page_count = 2},
	};

	send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RO, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Attempt to share the same area of memory. */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  service1_info->vm_id);

	/* Ensure we can't donate any sub section of memory to another VM. */
	constituents[0].page_count = 1;
	for (size_t i = 1; i < PAGE_SIZE * 2; i++) {
		constituents[0].address = (uint64_t)pages + PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service2_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_donate(msg_size, msg_size),
				 FFA_DENIED);
	}

	/* Ensure we can't donate to the only borrower. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_twice", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_lend_twice", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE * 4);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	/* Lend memory to VM1. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Attempt to lend the same area of memory. */
	check_cannot_lend_memory(mb, constituents, ARRAY_SIZE(constituents),
				 -1);
	/* Attempt to share the same area of memory. */
	check_cannot_share_memory(mb, constituents, ARRAY_SIZE(constituents),
				  -1);
	/* Fail to donate to VM apart from VM1. */
	check_cannot_donate_memory(mb, constituents, ARRAY_SIZE(constituents),
				   service1_info->vm_id);
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
				   service1_info->vm_id);

	/* Attempt to lend again with different permissions. */
	constituents[0].page_count = 1;
	for (size_t i = 0; i < 2; i++) {
		constituents[0].address = (uint64_t)pages + i * PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service2_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RO,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_lend_twice", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_lend_twice", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	handle = send_memory_and_retrieve_request(
		FFA_MEM_SHARE_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	/* Let the memory be accessed. */
	run_res = ffa_run(service1_info->vm_id, 0);
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
				   service1_info->vm_id);
	/* Fail to relinquish from any VM. */
	check_cannot_relinquish_memory(mb, handle);

	/* Attempt to share again with different permissions. */
	constituents[0].page_count = 1;
	for (size_t i = 0; i < 2; i++) {
		constituents[0].address = (uint64_t)pages + i * PAGE_SIZE;
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service2_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RO,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_return", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	/* Lend memory with clear flag. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents),
		FFA_MEMORY_REGION_FLAG_CLEAR, 0, FFA_DATA_ACCESS_RO,
		FFA_DATA_ACCESS_RO, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_X, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);
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
TEST_PRECONDITION(memory_sharing, share_clear, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t msg_size;
	size_t i;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_return", mb.send);

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages) * 2, 'b', PAGE_SIZE * 2);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0,
			  FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RO,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
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
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_check_upper_bound", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_check_upper_bound", mb.send);

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
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

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
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * FF-A: Verify past the lower bound of the lent region cannot be accessed.
 */
TEST(memory_sharing, ffa_lend_check_lower_bounds)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_check_lower_bound", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_check_lower_bound", mb.send);

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
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service1_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));

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
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Memory can't be shared if flags in the memory transaction description that
 * Must Be Zero, are not.
 */
TEST_PRECONDITION(memory_sharing, ffa_validate_mbz, hypervisor_only)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
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
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0xffffffff,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Using the same region, call the various mem send functions. */
	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);
	}
}

/**
 * Memory can't be shared with arbitrary attributes because Hafnium maps pages
 * with hardcoded values and doesn't support custom mappings.
 */
TEST_PRECONDITION(memory_sharing, ffa_validate_attributes, hypervisor_only)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	struct {
		enum ffa_memory_type memory_type;
		enum ffa_memory_cacheability memory_cacheability;
		enum ffa_memory_shareability memory_shareability;
	} invalid_attributes[] = {
		/* Invalid memory type */
		{FFA_MEMORY_DEVICE_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		 FFA_MEMORY_INNER_SHAREABLE},
		/* Invalid cacheability */
		{FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_NON_CACHEABLE,
		 FFA_MEMORY_INNER_SHAREABLE},
		/* Invalid shareability */
		{FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		 FFA_MEMORY_SHARE_NON_SHAREABLE},
		{FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		 FFA_MEMORY_OUTER_SHAREABLE}};

	for (uint32_t i = 0; i < ARRAY_SIZE(invalid_attributes); ++i) {
		/* Prepare memory region, and set all flags */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service1_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RO,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  invalid_attributes[i].memory_type,
				  invalid_attributes[i].memory_cacheability,
				  invalid_attributes[i].memory_shareability,
				  NULL, NULL, &msg_size),
			  0);

		/* Call the various mem send functions on the same region. */
		ret = ffa_mem_share(msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_EQ(ffa_error_code(ret), FFA_DENIED);
	}
}

/**
 * Memory can't be shared if the reserved_0 field in the ffa memory access
 * descriptor is not 0. This is checked for both v1.0 and v1.1 memory access
 * descriptors as the position of the reserved_0 moves.
 */
TEST(memory_sharing_v1_1, ffa_validate_memory_access_reserved_mbz)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
		ffa_mem_donate,
	};
	struct ffa_memory_access *receiver;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	/* Check memory access reserved_0 mbz is enforced for v1.0 and v1.1. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	receiver = ffa_memory_region_get_receiver(mb.send, 0);
	receiver->reserved_0 = 0xFFFFFFFF;

	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);
	}
}

TEST(memory_sharing_v1_0, ffa_validate_memory_access_reserved_mbz)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
		ffa_mem_donate,
	};
	struct ffa_memory_access_v1_0 receiver_v1_0;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	ffa_memory_access_init_v1_0(&receiver_v1_0, service1_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	receiver_v1_0.reserved_0 = 0xFFFFFFFF;

	/* Initialize memory sharing test according to v1.0. */
	ffa_memory_region_init_v1_0(
		(struct ffa_memory_region_v1_0 *)mb.send, HF_MAILBOX_SIZE,
		hf_vm_get_id(), &receiver_v1_0, 1, constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL,
		&msg_size);

	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);
	}
}

/**
 * Check that large values for the memory access descriptor size
 * and receiver count return INVALID_PARAMETERS and cannot be used
 * to access data outside of the receivers array.
 */
TEST(memory_sharing, ffa_memory_access_no_overflow)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
		ffa_mem_donate,
	};
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	/*
	 * Check a large memory_access_desc_size cannot be used to access
	 * memory out of bounds of the recievers array.
	 */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	memory_region->memory_access_desc_size =
		2 * sizeof(struct ffa_memory_access);

	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_ERROR_32);
		EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check receiver_count cannot be used to access
	 * memory out of bounds of the recievers array.
	 */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0,
			  FFA_DATA_ACCESS_NOT_SPECIFIED,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	memory_region->receiver_count = MAX_MEM_SHARE_RECIPIENTS;

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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
	};

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	unsigned invalid_flags[] = {
		0xFFFFFFFF, /* Incorrect transaction type [4:3]*/
		0xFFFFFFE0, /* Unsupported address range limit hint [9] */
		0xFFFFFDE0, /* [8:5] MBZ when not asking for address range */
		0xFFFFFC00  /* [31:10] MBZ */
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		/* Prepare memory region, and set all flags */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service1_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RW,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  send_function[i] == ffa_mem_share
					  ? FFA_MEMORY_NORMAL_MEM
					  : FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);

		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);

		handle = ffa_mem_success_handle(ret);

		for (unsigned int j = 0; j < ARRAY_SIZE(invalid_flags); ++j) {
			send_retrieve_request_single_receiver(
				mb.send, handle, hf_vm_get_id(),
				service1_info->vm_id, 0, invalid_flags[j],
				FFA_DATA_ACCESS_RW,
				FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				FFA_MEMORY_NORMAL_MEM,
				FFA_MEMORY_CACHE_WRITE_BACK,
				FFA_MEMORY_INNER_SHAREABLE, NULL);
			EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func,
				  FFA_YIELD_32);
		}

		EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	}
}

/**
 * Check a different value for the impdef field of the receiver struct
 * between the memory send transaction and the retrieve request causes
 * the retrieve request to fail with FFA_INVALID_PARAMETERS and the
 * memory to not be allocated to the endpoint.
 */
TEST(memory_sharing, ffa_validate_impdef_equal)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
	};

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access_impdef primary_vm_impdef_val =
		ffa_memory_access_impdef_init(0xAAAA, 0xBBBB);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(0xCCCC, 0xDDDD);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	for (unsigned int i = 0; i < ARRAY_SIZE(send_function); i++) {
		/* Prepare memory region, and set all flags */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service1_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RW,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  send_function[i] == ffa_mem_share
					  ? FFA_MEMORY_NORMAL_MEM
					  : FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE,
				  &primary_vm_impdef_val, NULL, &msg_size),
			  0);

		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);

		handle = ffa_mem_success_handle(ret);

		send_retrieve_request_single_receiver(
			mb.send, handle, hf_vm_get_id(), service1_info->vm_id,
			0, 0, FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE, &service1_impdef_val);

		EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

		EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	}
}
/**
 * Memory can't be shared with arbitrary attributes because Hafnium maps pages
 * with hardcoded values and doesn't support custom mappings.
 */
TEST(memory_sharing, ffa_validate_retrieve_req_attributes)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_share,
		ffa_mem_lend,
	};

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);

	struct {
		enum ffa_memory_type memory_type;
		enum ffa_memory_cacheability memory_cacheability;
		enum ffa_memory_shareability memory_shareability;
	} invalid_attributes[] = {
		/* Invalid memory type */
		{FFA_MEMORY_DEVICE_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		 FFA_MEMORY_INNER_SHAREABLE},
		/* Invalid cacheability */
		{FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_NON_CACHEABLE,
		 FFA_MEMORY_INNER_SHAREABLE},
		/* Invalid shareability */
		{FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		 FFA_MEMORY_SHARE_NON_SHAREABLE},
		{FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		 FFA_MEMORY_OUTER_SHAREABLE}};

	for (uint32_t i = 0; i < ARRAY_SIZE(send_function); i++) {
		/* Prepare memory region, and set all flags */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service1_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  FFA_DATA_ACCESS_RW,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  send_function[i] == ffa_mem_share
					  ? FFA_MEMORY_NORMAL_MEM
					  : FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);

		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);

		handle = ffa_mem_success_handle(ret);

		for (uint32_t j = 0; j < ARRAY_SIZE(invalid_attributes); ++j) {
			send_retrieve_request_single_receiver(
				mb.send, handle, hf_vm_get_id(),
				service1_info->vm_id, 0, 0, FFA_DATA_ACCESS_RW,
				FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				invalid_attributes[j].memory_type,
				invalid_attributes[j].memory_cacheability,
				invalid_attributes[j].memory_shareability,
				NULL);
			EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func,
				  FFA_YIELD_32);
		}

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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	/* If mem share can't clear memory before sharing. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0,
			  FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_TRUE(ffa_error_code(ret) == FFA_INVALID_PARAMETERS);

	/*
	 * Same should happen when using FFA_MEM_RETRIEVE interface.
	 * Attempt to successfully share, and validate error return in the
	 * receiver.
	 */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	handle = ffa_mem_success_handle(ret);

	/* Prepare retrieve request setting clear memory flags. */
	send_retrieve_request_single_receiver(
		mb.send, handle, hf_vm_get_id(), service1_info->vm_id, 0,
		FFA_MEMORY_REGION_FLAG_CLEAR |
			FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH,
		FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

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
	struct ffa_partition_info *service1_info = service1(mb.recv);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);

	/* Call FFA_MEM_SEND, setting FFA_DATA_ACCESS_RO. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RO,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	handle = ffa_mem_success_handle(ret);

	/*
	 * Prepare retrieve request with RO, and setting flag to clear memory.
	 * Should fail at the receiver's FFA_MEM_RETRIEVE call.
	 * Using the FFA_MEMORY_REGION_FLAG_CLEAR.
	 */
	send_retrieve_request_single_receiver(
		mb.send, handle, hf_vm_get_id(), service1_info->vm_id, 0,
		FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NX, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/*
	 * Using the FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH flag.
	 */
	send_retrieve_request_single_receiver(
		mb.send, handle, hf_vm_get_id(), service1_info->vm_id, 0,
		FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH, FFA_DATA_ACCESS_RO,
		FFA_INSTRUCTION_ACCESS_NX, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Reclaiming memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}

/**
 * A borrower can only request a memory region to be cleared on his end, if
 * the sender has set the FFA_MEMORY_REGION_FLAG_CLEAR flag in the transaction
 * descriptor. If the sender flag is clear, expect FFA_DENIED error.
 */
TEST(memory_sharing, ffa_validate_retrieve_req_clear_flag_if_sender_not_clear)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_lend,
		ffa_mem_donate,
	};
	struct ffa_partition_info *service1_info = service1(mb.recv);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);

	for (uint32_t i = 0; i < ARRAY_SIZE(send_function); i++) {
		/*
		 * Call FF-A memory send interface, not setting the
		 * FFA_MEMORY_REGION_FLAG_CLEAR.
		 */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service1_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  /* Different args for lend and donate. */
				  send_function[i] == ffa_mem_lend
					  ? FFA_DATA_ACCESS_RW
					  : FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);

		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);

		handle = ffa_mem_success_handle(ret);

		/*
		 * Prepare retrieve request with RW, and setting flag to clear
		 * memory. Should fail at the receiver's FFA_MEM_RETRIEVE_REQ
		 * call with FFA_DENIED.
		 */
		send_retrieve_request_single_receiver(
			mb.send, handle, hf_vm_get_id(), service1_info->vm_id,
			0, FFA_MEMORY_REGION_FLAG_CLEAR, FFA_DATA_ACCESS_RW,
			/* Different args for lend and donate. */
			send_function[i] == ffa_mem_lend
				? FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED
				: FFA_INSTRUCTION_ACCESS_NX,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE, NULL);

		EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
		EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	}
}

/**
 * If the borrower specifies the transaction type in the flags of the memory
 * region descriptor, and it doesn't match operation performed by sender,
 * call to FFA_RETRIEVE_REQ must fail.
 */
TEST(memory_sharing, ffa_validate_retrieve_transaction_type)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_lend,
		ffa_mem_share,
		ffa_mem_donate,
	};
	struct ffa_partition_info *service1_info = service1(mb.recv);

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	for (uint32_t i = 0; i < ARRAY_SIZE(send_function); i++) {
		/* Call the memory share interface. */
		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
				  service1_info->vm_id, constituents,
				  ARRAY_SIZE(constituents), 0, 0,
				  send_function[i] != ffa_mem_donate
					  ? FFA_DATA_ACCESS_RW
					  : FFA_DATA_ACCESS_NOT_SPECIFIED,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  send_function[i] == ffa_mem_share
					  ? FFA_MEMORY_NORMAL_MEM
					  : FFA_MEMORY_NOT_SPECIFIED_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);

		ret = send_function[i](msg_size, msg_size);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);

		handle = ffa_mem_success_handle(ret);

		/*
		 * Prepare retrieve request with RW, and set the transaction
		 * type wrongly in the memory region flags.
		 * Should fail at the receiver's FFA_MEM_RETRIEVE_REQ
		 * call with FFA_INVALID_PARAMETERS.
		 */
		send_retrieve_request_single_receiver(
			mb.send, handle, hf_vm_get_id(), service1_info->vm_id,
			0,
			send_function[i] == ffa_mem_share
				? FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND
				: FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE,
			FFA_DATA_ACCESS_RW,
			send_function[i] != ffa_mem_donate
				? FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED
				: FFA_INSTRUCTION_ACCESS_NX,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE, NULL);

		EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

		EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	}
}

void memory_retrieve_multiple_borrower_base(void *send, ffa_id_t recipient,
					    ffa_memory_handle_t handle,
					    struct ffa_memory_access *receivers,
					    uint32_t receiver_count,
					    uint8_t *ptr, uint32_t flags)
{
	SERVICE_SELECT(recipient, "memory_increment", send);

	/*
	 * Send the appropriate retrieve request to the VM so that it
	 * can use it to retrieve the memory.
	 */
	send_retrieve_request(send, handle, hf_vm_get_id(), receivers,
			      receiver_count, 0, flags, FFA_MEMORY_NORMAL_MEM,
			      FFA_MEMORY_CACHE_WRITE_BACK,
			      FFA_MEMORY_INNER_SHAREABLE, recipient);
	EXPECT_EQ(ffa_run(recipient, 0).func, FFA_YIELD_32);

	for (uint32_t i = 0; i < PAGE_SIZE; ++i) {
		ptr[i] = i;
	}

	EXPECT_EQ(ffa_run(recipient, 0).func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		/* Should have been incremented by each receiver. */
		uint8_t value = i + 1;
		EXPECT_EQ(ptr[i], value);
	}
}

/**
 * Validate that sender can specify multiple borrowers to memory share
 * operation.
 */
TEST(memory_sharing, mem_share_multiple_borrowers)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_memory_region *mem_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access receivers[2];
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	ffa_memory_region_init(
		mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(), receivers,
		ARRAY_SIZE(receivers), sizeof(struct ffa_memory_access),
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, &msg_size, NULL);

	ret = ffa_mem_share(msg_size, msg_size);

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	for (uint32_t j = 0; j < ARRAY_SIZE(receivers); j++) {
		ffa_id_t recipient = receivers[j].receiver_permissions.receiver;

		memory_retrieve_multiple_borrower_base(
			mb.send, recipient, handle, receivers,
			ARRAY_SIZE(receivers), pages,
			FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE);
	}
}

/**
 * Memory sharing operation with multiple borrowers, bypassing multiple borrower
 * checks. The borrowers will only provide their own permissions.
 */
TEST(memory_sharing, mem_share_bypass_multiple_borrowers)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	uint8_t *ptr = pages;
	struct ffa_memory_region *mem_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access receivers[2];
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	ffa_memory_region_init(
		mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(), receivers,
		ARRAY_SIZE(receivers), sizeof(struct ffa_memory_access),
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, &msg_size, NULL);

	ret = ffa_mem_share(msg_size, msg_size);

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	for (uint32_t j = 0; j < ARRAY_SIZE(receivers); j++) {
		ffa_id_t recipient = receivers[j].receiver_permissions.receiver;

		/* Set the flag to bypass multiple borrower checks. */
		memory_retrieve_multiple_borrower_base(
			mb.send, recipient, handle, &receivers[j], 1, ptr,
			FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE |
				FFA_MEMORY_REGION_FLAG_BYPASS_BORROWERS_CHECK);
	}
}

TEST(memory_sharing, mem_share_bypass_multiple_borrowers_wrong_receiver_count)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_memory_region *mem_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access receivers[2];
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_msg *retrieve_message = mb.send;
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	ffa_memory_region_init(
		mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(), receivers,
		ARRAY_SIZE(receivers), sizeof(struct ffa_memory_access),
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, &msg_size, NULL);

	ret = ffa_mem_share(msg_size, msg_size);

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	handle = ffa_mem_success_handle(ret);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		own_id, receivers, ARRAY_SIZE(receivers),
		sizeof(struct ffa_memory_access), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE |
			FFA_MEMORY_REGION_FLAG_BYPASS_BORROWERS_CHECK,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ffa_rxtx_header_init(own_id, service1_info->vm_id, msg_size,
			     &retrieve_message->header);

	ASSERT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
}

/**
 * Validate that sender can specify multiple borrowers to memory lend
 * operation. All receivers will increment the content of the first page and
 * relinquish access to the region. The sender shall reclaim access to it.
 */
TEST(memory_sharing, mem_lend_relinquish_reclaim_multiple_borrowers)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_access receivers[2];
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	/*
	 * To prove the receiver can relinquish and retrieve whilst sender
	 * didn't reclaim.
	 */
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);

	SERVICE_SELECT(service1_info->vm_id, "memory_increment_relinquish",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "memory_increment_relinquish",
		       mb.send);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents), receivers,
		receivers, ARRAY_SIZE(receivers), FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK, 2, false,
		false);

	/*
	 * Try lending with the Zero memory flag set.
	 * The Zero memory after relinquish flag in the relinquish
	 * request should take priority so even with this set we
	 * should still see the pointer values incremented.
	 */
	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents), receivers,
		receivers, ARRAY_SIZE(receivers), FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK, 2, true,
		false);
}

/**
 * Validate that sender can't specify multiple borrowers to memory donate
 * operation.
 */
TEST_PRECONDITION(memory_sharing, fail_if_multi_receiver_donate,
		  hypervisor_only)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_memory_region *mem_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access receivers[2];
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	ffa_memory_region_init(
		mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(), receivers,
		ARRAY_SIZE(receivers), sizeof(struct ffa_memory_access),
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size);

	ret = ffa_mem_donate(msg_size, msg_size);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

static void fail_multiple_receiver_mem_share_lend(
	struct ffa_memory_region *mem_region, ffa_id_t receiver_id1,
	ffa_id_t receiver_id2, enum ffa_data_access data_access1,
	enum ffa_data_access data_access2,
	enum ffa_instruction_access instruction_access1,
	enum ffa_instruction_access instruction_access2)
{
	struct ffa_value ret;
	struct ffa_value (*send_function[])(uint32_t, uint32_t) = {
		ffa_mem_lend,
		ffa_mem_share,
	};
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access receivers[2];
	uint32_t msg_size;
	struct ffa_memory_access_impdef receiver1_impdef_val =
		ffa_memory_access_impdef_init(receiver_id1, receiver_id1 + 1);
	struct ffa_memory_access_impdef receiver2_impdef_val =
		ffa_memory_access_impdef_init(receiver_id2, receiver_id2 + 1);

	ffa_memory_access_init(&receivers[0], receiver_id1, data_access1,
			       instruction_access1, 0, &receiver1_impdef_val);

	ffa_memory_access_init(&receivers[1], receiver_id2, data_access2,
			       instruction_access2, 0, &receiver2_impdef_val);

	ffa_memory_region_init(
		mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(), receivers,
		ARRAY_SIZE(receivers), sizeof(struct ffa_memory_access),
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size);

	for (uint32_t i = 0U; i < ARRAY_SIZE(send_function); i++) {
		ret = send_function[i](msg_size, msg_size);
		EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
	}
}

/**
 * Validate that operation fails if at least one of the borroweres is given
 * invalid permissions.
 */
TEST_PRECONDITION(memory_sharing, fail_if_one_receiver_wrong_permissions,
		  hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	/* The 2nd specified receiver has X permissions for the memory. */
	fail_multiple_receiver_mem_share_lend(
		mb.send, service1_info->vm_id, service2_info->vm_id,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_X);
}

/**
 * Validate that sender can't repeat a borrower in the memory transaction
 * descriptor.
 */
TEST_PRECONDITION(memory_sharing, fail_if_repeated_borrower, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	/* Used the same borrower ID. */
	fail_multiple_receiver_mem_share_lend(
		mb.send, service1_info->vm_id, service1_info->vm_id,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED);
}

/**
 * Validate that sender can't specify its own id as a receiver.
 */
TEST_PRECONDITION(memory_sharing, fail_if_one_receiver_is_self, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	/* Use own id. */
	fail_multiple_receiver_mem_share_lend(
		mb.send, service1_info->vm_id, hf_vm_get_id(),
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED);
}

/**
 * Check that memory can be lent and retrieved with multiple fragments, in the
 * multiple receiver scenario.
 */
TEST(memory_sharing, lend_fragmented_relinquish_multi_receiver)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t i;
	ffa_memory_handle_t handle;
	struct ffa_memory_access receivers[2];
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	for (i = 0; i < ARRAY_SIZE(receivers); i++) {
		ffa_id_t vm_id = receivers[i].receiver_permissions.receiver;
		SERVICE_SELECT(vm_id, "ffa_memory_lend_relinquish", mb.send);
	}

	/* Initialise the memory before giving it. */
	memset_s(ptr, sizeof(pages), 'b',
		 PAGE_SIZE * FRAGMENTED_SHARE_PAGE_COUNT);

	for (i = 0; i < ARRAY_SIZE(constituents_lend_fragmented_relinquish);
	     ++i) {
		constituents_lend_fragmented_relinquish[i].address =
			(uint64_t)pages + i * PAGE_SIZE;
		constituents_lend_fragmented_relinquish[i].page_count = 1;
		constituents_lend_fragmented_relinquish[i].reserved = 0;
	}

	handle = send_memory_and_retrieve_request_multi_receiver(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(),
		constituents_lend_fragmented_relinquish,
		ARRAY_SIZE(constituents_lend_fragmented_relinquish), receivers,
		ARRAY_SIZE(receivers), receivers, ARRAY_SIZE(receivers), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);

	for (i = 0; i < ARRAY_SIZE(receivers); i++) {
		ffa_id_t vm_id = receivers[i].receiver_permissions.receiver;
		run_res = ffa_run(vm_id, 0);
		/* Let the memory be returned. */
		EXPECT_EQ(run_res.func, FFA_YIELD_32);
	}

	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Ensure that both borrowers accessed the region. */
	for (i = 0; i < PAGE_SIZE * FRAGMENTED_SHARE_PAGE_COUNT; ++i) {
		ASSERT_EQ(ptr[i], 'd');
	}

	/* Check that subsequents accesses to the memory fail. */
	for (i = 0; i < ARRAY_SIZE(receivers); i++) {
		ffa_id_t vm_id = receivers[i].receiver_permissions.receiver;
		run_res = ffa_run(vm_id, 0);
		EXPECT_TRUE(exception_received(&run_res, mb.recv));
	}
}

/**
 * For the v1.1 transaction descriptor it is the case that the memory
 * access descriptor is smaller than the descriptor for the current
 * version. Therefore, we test that sending the smaller descriptor with
 * the correct memory access descriptor size in the memory region
 * descriptor passes as expected.
 */
TEST(memory_sharing_v1_1, share_ffa_v1_1_to_current_version)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};
	/* v1.1 and v1.0 share the same memory access descriptors */
	struct ffa_memory_access_v1_0 receivers_v1_1[2];
	struct ffa_memory_access receivers_v_cur[2];
	uint32_t msg_size;
	struct ffa_partition_msg *retrieve_message = mb.send;
	uint8_t *ptr = pages;
	ffa_memory_handle_t handle;

	SERVICE_SELECT(service2_info->vm_id, "memory_increment", mb.send);

	ffa_memory_access_init_v1_0(&receivers_v1_1[0], service1_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	ffa_memory_access_init(&receivers_v_cur[0], service1_info->vm_id,
			       FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, NULL);

	ffa_memory_access_init_v1_0(&receivers_v1_1[1], service2_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	ffa_memory_access_init(&receivers_v_cur[1], service2_info->vm_id,
			       FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, NULL);

	ffa_memory_region_init(
		(struct ffa_memory_region *)mb.send, HF_MAILBOX_SIZE,
		hf_vm_get_id(), (void *)receivers_v1_1,
		ARRAY_SIZE(receivers_v1_1),
		sizeof(struct ffa_memory_access_v1_0), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL,
		&msg_size);

	/* Set current version to FF-A v1.1. */
	EXPECT_EQ(ffa_version(FFA_VERSION_1_1), FFA_VERSION_COMPILED);

	ret = ffa_mem_share(msg_size, msg_size);

	handle = ffa_mem_success_handle(ret);

	/* Send v1.current retrieve to the borrower. */
	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		hf_vm_get_id(), receivers_v_cur, ARRAY_SIZE(receivers_v_cur),
		sizeof(struct ffa_memory_access), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	ffa_rxtx_header_init(hf_vm_get_id(), service2_info->vm_id, msg_size,
			     &retrieve_message->header);
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);

	/* Run service2 for it to fetch memory, and then use memory. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);

	for (uint32_t i = 0; i < PAGE_SIZE; ++i) {
		ptr[i] = i;
	}

	/* Run service2 for it access memory. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);

	for (size_t i = 0; i < PAGE_SIZE; ++i) {
		/* Should have been incremented by each receiver. */
		uint8_t value = i + 1;
		EXPECT_EQ(ptr[i], value);
	}

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * For the v1.1 transaction descriptor it is the case that the memory
 * access descriptor is smaller than the descriptor for the current
 * version. Sending a current memory descriptor to a v1_1 endpoint
 * should still be possible this test checks that is the case.
 */
TEST(memory_sharing, share_ffa_current_version_to_v1_1)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};
	/* v1.1 receivers match the fields from v1.0 */
	struct ffa_memory_access_v1_0 receivers_v1_1[2];
	struct ffa_memory_access receivers_v_cur[2];
	uint32_t msg_size;
	struct ffa_partition_msg *retrieve_message = mb.send;
	ffa_memory_handle_t handle;
	uint8_t *ptr = pages;

	SERVICE_SELECT(service1_info->vm_id, "retrieve_ffa_v1_1", mb.send);

	ffa_memory_access_init_v1_0(&receivers_v1_1[0], service1_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	ffa_memory_access_init(&receivers_v_cur[0], service1_info->vm_id,
			       FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, NULL);
	ffa_memory_access_init_v1_0(&receivers_v1_1[1], service2_info->vm_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	ffa_memory_access_init(&receivers_v_cur[1], service2_info->vm_id,
			       FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, NULL);

	/* Initialize memory sharing test according to current version. */
	ffa_memory_region_init(
		(struct ffa_memory_region *)mb.send, HF_MAILBOX_SIZE,
		hf_vm_get_id(), receivers_v_cur, ARRAY_SIZE(receivers_v_cur),
		sizeof(struct ffa_memory_access), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL,
		&msg_size);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_NE(ret.func, FFA_ERROR_32);

	handle = ffa_mem_success_handle(ret);

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		hf_vm_get_id(), (void *)receivers_v1_1,
		ARRAY_SIZE(receivers_v1_1),
		sizeof(struct ffa_memory_access_v1_0), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);
	ffa_rxtx_header_init(hf_vm_get_id(), service1_info->vm_id, msg_size,
			     &retrieve_message->header);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Initialise the memory before giving it. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		ptr[i] = i;
	}

	/* Run service1 to access memory. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		uint8_t val = i + 1;
		ASSERT_EQ(ptr[i], val);
	}
}

/**
 * Test that a v1.1 SP can share memory to multiple endpoints, and
 * that the endpoints can access and modify it.
 */
TEST_PRECONDITION(memory_sharing, v1_1_service_shares_memory,
		  service1_service2_and_service3_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "share_ffa_v1_1", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "retrieve_ffa_v1_1", mb.send);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Validate that a borrower can't retrieve memory if the fragments aren't
 * totally sent.
 */
TEST(memory_sharing, fail_fragmented_if_retrieve_before_sent)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_memory_region *mem_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t remaining_constituent_count;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_msg *retrieve_message = mb.send;
	uint32_t fragment_length;
	uint32_t total_length;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	/* Send everything except the last constituent in the first fragment. */
	remaining_constituent_count = ffa_memory_region_init_single_receiver(
		mem_region, HF_MAILBOX_SIZE, hf_vm_get_id(),
		service1_info->vm_id, constituents, ARRAY_SIZE(constituents), 0,
		0, FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL, &total_length,
		&fragment_length);
	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(total_length, fragment_length);

	/* Don't include the last constituent in the first fragment. */
	fragment_length -= sizeof(struct ffa_memory_region_constituent);

	ret = ffa_mem_share(total_length, fragment_length);
	EXPECT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	handle = ffa_frag_handle(ret);

	/*
	 * Send the appropriate retrieve request to the VM so that it can use
	 * it.
	 */
	msg_size = ffa_memory_retrieve_request_init_single_receiver(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		hf_vm_get_id(), service1_info->vm_id, 0, 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL);
	ffa_rxtx_header_init(hf_vm_get_id(), service1_info->vm_id, msg_size,
			     &retrieve_message->header);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
}

/**
 * Clear memory flags with only one receiver.
 */
TEST(memory_sharing, lend_zero_memory_after_relinquish)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	ffa_memory_handle_t handle;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_msg *retrieve_message = mb.send;
	uint8_t *ptr = pages;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(
		service1_info->vm_id,
		"memory_increment_relinquish_with_clear_check_not_zeroed",
		mb.send);

	/* If mem share can't clear memory before sharing. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Write to memory. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		ptr[i] = i;
	}

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_error_code(ret), 0);

	handle = ffa_mem_success_handle(ret);

	/* Prepare retrieve request setting clear memory flags. */
	msg_size = ffa_memory_retrieve_request_init_single_receiver(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		hf_vm_get_id(), service1_info->vm_id, 0,
		FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NX, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ffa_rxtx_header_init(hf_vm_get_id(), service1_info->vm_id, msg_size,
			     &retrieve_message->header);
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
	/* Run to retrieve memory. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/*
	 * Run such that SP can retrieve the memory, and check it is not zeroed.
	 */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Run such that SP can use and relinquish memory. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Reestablish exclusive access to memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		EXPECT_EQ(ptr[i], 0);
	}

	/*
	 * Try lending without the Zero memory flag set.
	 * The Zero memory after relinquish flag in the relinquish
	 * request should take priority so we should still see the
	 * memory zeroed.
	 */

	/* If mem share can't clear memory before sharing. */
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/* Write to memory. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		ptr[i] = i;
	}

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_error_code(ret), 0);

	handle = ffa_mem_success_handle(ret);

	/* Prepare retrieve request without setting clear memory flags. */
	msg_size = ffa_memory_retrieve_request_init_single_receiver(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		hf_vm_get_id(), service1_info->vm_id, 0, 0, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NX, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE, NULL);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ffa_rxtx_header_init(hf_vm_get_id(), service1_info->vm_id, msg_size,
			     &retrieve_message->header);
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
	/* Run to retrieve memory. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/*
	 * Run such that SP can retrieve the memory, and check it is not zeroed.
	 */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Run such that SP can use and relinquish memory. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Reestablish exclusive access to memory. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		EXPECT_EQ(ptr[i], 0);
	}
}

/**
 * Clear memory flag with multiple receivers:
 * - Both test services retrieve memory.
 * - Service1 sets clear memory on relinquish flag.
 * - Service1 uses it and relinquishes access.
 * - Service2 uses it and checks its contents are not zeroed.
 * - Service2 relinquishes access.
 * - This partition reclaims and checks memory has been zeroed.
 */
TEST(memory_sharing, lend_zero_memory_after_relinquish_multiple_borrowers)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_access receivers[2];
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_access_impdef service1_impdef_val =
		ffa_memory_access_impdef_init(service1_info->vm_id,
					      service1_info->vm_id + 1);
	struct ffa_memory_access_impdef service2_impdef_val =
		ffa_memory_access_impdef_init(service2_info->vm_id,
					      service2_info->vm_id + 1);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "memory_increment_relinquish_with_clear", mb.send);

	/* Before incrementing memory service2 checks memory is not cleared. */
	SERVICE_SELECT(
		service2_info->vm_id,
		"memory_increment_relinquish_with_clear_check_not_zeroed",
		mb.send);

	ffa_memory_access_init(
		&receivers[0], service1_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service1_impdef_val);

	ffa_memory_access_init(
		&receivers[1], service2_info->vm_id, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &service2_impdef_val);

	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents), receivers,
		receivers, ARRAY_SIZE(receivers), FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK, 1, true,
		true);

	/*
	 * Try lending without the Zero memory flag set.
	 * The Zero memory after relinquish flag in the relinquish
	 * request should take priority so we should still see the
	 * memory zeroed.
	 */
	lend_and_check_memory_increment(
		&mb, constituents, ARRAY_SIZE(constituents), receivers,
		receivers, ARRAY_SIZE(receivers), FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK, 1, false,
		true);
}

TEST_PRECONDITION(memory_sharing, fail_inconsistent_page_count, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
	};

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  memory_region, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	/*
	 * Change the count of composite for the ffa_mem_share call to return
	 * error.
	.*/
	composite = ffa_memory_region_get_composite(memory_region, 0);

	ASSERT_TRUE(composite != NULL);

	if (composite != NULL) {
		composite->page_count = 100;
	}

	EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size),
			 FFA_INVALID_PARAMETERS);
}

/*
 * As per FF-A v1.1 EAC0 specification, section 10.11.3.1, the memory ranges
 * specified in the composite memory region descriptor shall not overlap.
 * This test validates the error return, if memory ranges do overlap.
 * The following test doesn't require a world switch. So running test, once
 * in the system configuration with only the hypervisor should suffice. The
 * related code is common to SPMC and Hypervisor targets.
 */
TEST_PRECONDITION(memory_sharing, fail_page_overlap, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t msg_size;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)mb.send;
	struct ffa_memory_region_constituent constituents[3][2] = {
		{{.address = (uint64_t)pages, .page_count = 5},
		 {.address = (uint64_t)pages + PAGE_SIZE, .page_count = 2}},
		{{.address = (uint64_t)pages, .page_count = 5},
		 {.address = (uint64_t)pages, .page_count = 5}},
		{{.address = (uint64_t)pages, .page_count = 5},
		 {.address = (uint64_t)pages + PAGE_SIZE * 3,
		  .page_count = 2}}};

	for (uint32_t i = 0; i < ARRAY_SIZE(constituents); i++) {
		HFTEST_LOG("Testing constituents in position: %x\n", i);

		EXPECT_EQ(ffa_memory_region_init_single_receiver(
				  memory_region, HF_MAILBOX_SIZE,
				  hf_vm_get_id(), service1_info->vm_id,
				  constituents[i], ARRAY_SIZE(constituents[i]),
				  0, 0, FFA_DATA_ACCESS_RW,
				  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
				  FFA_MEMORY_NORMAL_MEM,
				  FFA_MEMORY_CACHE_WRITE_BACK,
				  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL,
				  &msg_size),
			  0);
		EXPECT_FFA_ERROR(ffa_mem_share(msg_size, msg_size),
				 FFA_INVALID_PARAMETERS);
	}
}

/**
 * FFA_MEM_LEND/FFA_MEM_DONATE shall fail if retriever doesn't specify the
 * instruction permissions.
 */
TEST(memory_sharing, retrieve_instruction_access_not_specified)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	uint32_t func_ids[] = {
		FFA_MEM_LEND_32,
		FFA_MEM_DONATE_32,
	};
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_share_fail_invalid_parameters", mb.send);

	memset_s(ptr, sizeof(pages), 'a', PAGE_SIZE);

	for (uint32_t i = 0; i < ARRAY_SIZE(func_ids); i++) {
		const enum ffa_data_access sender_data_permissions =
			(func_ids[i] == FFA_MEM_LEND_32)
				? FFA_DATA_ACCESS_RW
				: FFA_DATA_ACCESS_NOT_SPECIFIED;
		ffa_memory_handle_t handle = send_memory_and_retrieve_request(
			func_ids[i], mb.send, hf_vm_get_id(),
			service1_info->vm_id, constituents,
			ARRAY_SIZE(constituents), 0, 0, sender_data_permissions,
			FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			/*
			 * Not specified retrieve request instruction
			 * permissions.
			 */
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
			FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_CACHE_WRITE_BACK);
		EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
		ffa_mem_reclaim(handle, 0);
	}
}

/**
 * Validate that an SP can't share/lend/donate secure memory to a VM.
 */
TEST_PRECONDITION(memory_sharing, invalid_from_sp, service1_is_not_vm)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "invalid_memory_share", mb.send);

	/* Run SP to attempt to donate memory. */
	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Validate that memory marked as read only for the sender cannot have
 * the Zero Memory flag set during a memory lend or donate call.
 */
TEST_PRECONDITION(memory_sharing, cannot_zero_ro_memory_on_lend_or_donate,
		  service1_and_service2_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_fail_clear_ro_memory_on_lend_or_donate",
		       mb.send);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Validate that memory marked as read only for the sender cannot
 * have the Zero Memory flag set during the retrieve request.
 */
TEST_PRECONDITION(memory_sharing, cannot_zero_ro_memory_on_retrieve,
		  service1_and_service2_are_secure)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_memory_fail_clear_ro_memory_on_retrieve", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_share_fail_denied",
		       mb.send);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	/* Run service 2 to check request fails as expected. */
	run_res = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}
