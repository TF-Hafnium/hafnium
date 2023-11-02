/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa.h"
#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t
	pages[FRAGMENTED_SHARE_PAGE_COUNT * PAGE_SIZE];

/**
 * Test memory relinquish after a share and retrieve.
 */
TEST(memory_sharing, share_retrieve_relinquish)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = sp_req_retrieve_cmd_send(hf_vm_get_id(), service1_info->vm_id,
				       handle, tag, retrieve_flags);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);

	/* Expect SP to have incremented the page */
	EXPECT_EQ(pages[0], 1);
}

/**
 * Test memory relinquish after a share and retrieve.
 */
TEST(memory_sharing, fail_on_share_twice)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_value ret;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	ffa_mem_success_handle(ret);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);
	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

/**
 * Test memory relinquish after a lend and retrieve.
 */
TEST(memory_sharing, lend_retrieve_relinquish)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0x0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = sp_req_retrieve_cmd_send(hf_vm_get_id(), service1_info->vm_id,
				       handle, tag, retrieve_flags);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Test memory relinquish after a share and retrieve.
 */
TEST(memory_sharing, force_fragmented_share_retrieve_relinquish)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t constituent_count = ARRAY_SIZE(constituents);
	uint32_t msg_size;
	uint32_t fragment_length = 0;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, &msg_size,
			  &fragment_length),
		  0);
	EXPECT_EQ(msg_size, fragment_length);
	/* Don't include the last constituent in the first fragment. */
	fragment_length -= sizeof(struct ffa_memory_region_constituent);
	ret = ffa_mem_share(msg_size, fragment_length);
	EXPECT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	EXPECT_EQ(ret.arg3, fragment_length);

	handle = ffa_frag_handle(ret);

	/* Send the last constituent in a separate fragment. */
	ffa_memory_fragment_init(mb.send, HF_MAILBOX_SIZE,
				 &constituents[constituent_count - 1], 1,
				 &fragment_length);
	ret = ffa_mem_frag_tx(handle, fragment_length);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = sp_req_retrieve_cmd_send(hf_vm_get_id(), service1_info->vm_id,
				       handle, tag, retrieve_flags);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);

	/* Expect SP to have incremented the page */
	EXPECT_EQ(pages[0], 1);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Memory can't be shared with arbitrary attributes because Hafnium maps pages
 * with hardcoded values and doesn't support custom mappings.
 */
TEST(memory_sharing, ffa_validate_attributes)
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
				  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
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
 * Memory can't be shared if flags in the memory transaction description that
 * Must Be Zero, are not.
 */
TEST(memory_sharing, ffa_validate_mbz)
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
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
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
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Test memory reclaim after a lend but before a retrieve.
 */
TEST(memory_sharing, lend_reclaim_before_retrieve)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
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
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = sp_req_retrieve_cmd_send(hf_vm_get_id(), service1_info->vm_id,
				       handle, tag, retrieve_flags);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Test memory reclaim after a share but before a retrieve.
 */
TEST(memory_sharing, share_reclaim_before_retrieve)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t tag = 0xDEAD;
	uint32_t retrieve_flags = 0;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	memset_s(pages, PAGE_SIZE, 0, PAGE_SIZE);
	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  mb.send, HF_MAILBOX_SIZE, hf_vm_get_id(),
			  service1_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), tag, retrieve_flags,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}
