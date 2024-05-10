/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/ffa_v1_0.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t
	pages[FRAGMENTED_SHARE_PAGE_COUNT * PAGE_SIZE];

SET_UP(memory_sharing_v1_2)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_2), FFA_VERSION_COMPILED);
}

SET_UP(memory_sharing_v1_0)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_0), FFA_VERSION_COMPILED);
}

/** Test sharing memory from a v1.2 VM to a v1.0 SP. */
TEST(memory_sharing_v1_2, share_ffa_v1_2_to_v1_0)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();

	struct ffa_partition_info *service1_info = service1(mb.recv);
	const ffa_id_t receiver_id = service1_info->vm_id;
	const ffa_id_t sender_id = hf_vm_get_id();

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	struct ffa_memory_access receiver_v1_2;
	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(receiver_id, receiver_id + 1);

	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t handle;

	/* Initialise the memory before giving it. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		pages[i] = i;
	}

	ffa_memory_access_init(&receiver_v1_2, receiver_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);

	remaining_constituent_count = ffa_memory_region_init(
		mb.send, HF_MAILBOX_SIZE, sender_id, &receiver_v1_2, 1,
		sizeof(struct ffa_memory_access), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&fragment_length, &total_length);
	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(fragment_length, total_length);

	ret = ffa_mem_share(total_length, fragment_length);
	handle = ffa_mem_success_handle(ret);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_NE(handle, FFA_MEMORY_HANDLE_INVALID);

	ret = sp_ffa_mem_retrieve_cmd_send(sender_id, receiver_id, handle,
					   FFA_VERSION_1_0);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		uint8_t val = i + 1;
		ASSERT_EQ(pages[i], val);
	}
}

/** Test sharing memory from a v1.0 VM to a v1.2 SP. */
TEST(memory_sharing_v1_0, share_ffa_v1_0_to_v1_2)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();

	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;
	const ffa_id_t sender_id = hf_vm_get_id();

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	struct ffa_memory_access_v1_0 receiver_v1_0;

	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t handle;

	/* Initialise the memory before giving it. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		pages[i] = i;
	}

	ffa_memory_access_init_v1_0(&receiver_v1_0, receiver_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);

	/* Initialize memory sharing test according to v1.0. */
	remaining_constituent_count = ffa_memory_region_init_v1_0(
		mb.send, HF_MAILBOX_SIZE, sender_id, &receiver_v1_0, 1,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, &total_length, &fragment_length);

	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(total_length, fragment_length);

	ret = ffa_mem_share(total_length, fragment_length);
	handle = ffa_frag_handle(ret);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_NE(handle, FFA_MEMORY_HANDLE_INVALID);

	ret = sp_ffa_mem_retrieve_cmd_send(sender_id, receiver_id, handle,
					   FFA_VERSION_COMPILED);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		uint8_t val = i + 1;
		ASSERT_EQ(pages[i], val);
	}
}

/** Test fragmented sharing memory from a v1.0 VM to a v1.0 SP. */
TEST(memory_sharing_v1_0, force_fragmented_ffa_v1_0)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();

	struct ffa_partition_info *service1_info = service1(mb.recv);
	const ffa_id_t receiver_id = service1_info->vm_id;
	const ffa_id_t sender_id = hf_vm_get_id();

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};

	struct ffa_memory_access_v1_0 receiver_v1_0;

	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t handle;
	uint64_t allocator_mask;

	/* Initialise the memory before giving it. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		pages[i] = i;
	}

	ffa_memory_access_init_v1_0(&receiver_v1_0, receiver_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);

	/* Initialize memory sharing test according to v1.0. */
	remaining_constituent_count = ffa_memory_region_init_v1_0(
		mb.send, HF_MAILBOX_SIZE, sender_id, &receiver_v1_0, 1,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, &total_length, &fragment_length);

	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(total_length, fragment_length);

	/* Don't include the last constituent in the first fragment. */
	fragment_length -= sizeof(struct ffa_memory_region_constituent);
	remaining_constituent_count = 1;

	ret = ffa_mem_share(total_length, fragment_length);
	handle = ffa_frag_handle(ret);
	EXPECT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	EXPECT_NE(handle, FFA_MEMORY_HANDLE_INVALID);

	ASSERT_TRUE(!ffa_is_vm_id(sender_id) ||
		    !ffa_is_vm_id(service1_info->vm_id));
	allocator_mask = FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;

	send_fragmented_memory_region(
		&ret, mb.send, constituents, ARRAY_SIZE(constituents),
		remaining_constituent_count, fragment_length, total_length,
		&handle, allocator_mask);

	ret = sp_ffa_mem_retrieve_cmd_send(sender_id, receiver_id, handle,
					   FFA_VERSION_1_0);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		uint8_t val = i + 1;
		ASSERT_EQ(pages[i], val);
	}
}
