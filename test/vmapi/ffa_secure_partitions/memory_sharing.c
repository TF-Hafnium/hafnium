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

#if RXTX_MAX_PAGE_COUNT > 1
/*
 * Enough constituents that the retrieve response is bigger than one FF-A
 * page, so it dirties well past where the (single-constituent) real
 * retrieve response ends. Used to legitimately dirty the RX with non-zero
 * content ahead of the retrieve whose unpopulated tail is being checked.
 */
#define RX_FILLER_CONSTITUENT_COUNT \
	(FFA_PAGE_SIZE / sizeof(struct ffa_memory_region_constituent) + 8)
#endif

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

	ret = sp_increment_shared_buffer_cmd_send(sender_id, receiver_id);
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
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, 0);

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

	ret = sp_increment_shared_buffer_cmd_send(sender_id, receiver_id);
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
	enum ffa_memory_handle_allocator allocator;

	/* Initialise the memory before giving it. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		pages[i] = i;
	}

	ffa_memory_access_init_v1_0(&receiver_v1_0, receiver_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, 0);

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
	allocator = FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;

	send_fragmented_memory_region(
		&ret, &mb, constituents, ARRAY_SIZE(constituents),
		remaining_constituent_count, fragment_length, total_length,
		&handle, allocator);

	ret = sp_ffa_mem_retrieve_cmd_send(sender_id, receiver_id, handle,
					   FFA_VERSION_1_0);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	ret = sp_increment_shared_buffer_cmd_send(sender_id, receiver_id);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		uint8_t val = i + 1;
		ASSERT_EQ(pages[i], val);
	}
}

#if RXTX_MAX_PAGE_COUNT > 1
/*
 * Verify that the SPMC zeros the unpopulated tail of an SP's RX buffer after
 * writing a memory retrieve response (FF-A v1.3 section 4.10). The SP has a
 * multi-page mailbox; the retrieve response for a single constituent fits in
 * less than the full buffer.
 *
 * The SP can't pre-paint its own RX with a sentinel (the RX buffer is mapped
 * read-only to the owning endpoint), so a larger "filler" region is shared
 * and retrieved first: its response legitimately dirties the RX with
 * non-zero descriptor bytes. The SP then retrieves the "real" single-page
 * region and reports whether every byte past that response is zero, even
 * though the filler retrieve just wrote non-zero content there.
 */
TEST(memory_sharing_v1_2, retrieve_zeros_rx_tail_on_multi_page_mailbox)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t sender_id = hf_vm_get_id();

	struct ffa_partition_info *service1_info = service1(mb.recv);
	const ffa_id_t receiver_id = service1_info->vm_id;

	static struct ffa_memory_region_constituent
		filler_constituents[RX_FILLER_CONSTITUENT_COUNT];
	/*
	 * Use a page past the filler's range so the two regions don't
	 * overlap (a page can't be shared twice at once).
	 */
	struct ffa_memory_region_constituent real_constituents[] = {
		{.address = (uint64_t)pages +
			    RX_FILLER_CONSTITUENT_COUNT * PAGE_SIZE,
		 .page_count = 1},
	};

	struct ffa_memory_access receiver_v1_2;
	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(receiver_id, receiver_id + 1);

	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t filler_handle;
	ffa_memory_handle_t real_handle;

	for (uint32_t i = 0; i < RX_FILLER_CONSTITUENT_COUNT; i++) {
		filler_constituents[i].address =
			(uint64_t)pages + i * PAGE_SIZE;
		filler_constituents[i].page_count = 1;
	}

	/* Expand the SP's mailbox to multi-page so the tail check is
	 * meaningful. */
	ret = sp_remap_mailbox_cmd_send(sender_id, receiver_id,
					FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	/* Share the filler region with the SP, fragmenting the send side one
	 * page at a time as Hafnium requires. */
	ffa_memory_access_init(&receiver_v1_2, receiver_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);
	remaining_constituent_count = ffa_memory_region_init(
		mb.send, FFA_PAGE_SIZE, sender_id, &receiver_v1_2, 1,
		sizeof(struct ffa_memory_access), filler_constituents,
		ARRAY_SIZE(filler_constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&total_length, &fragment_length);
	ASSERT_GT(remaining_constituent_count, 0);

	ret = ffa_mem_share(total_length, fragment_length);
	filler_handle = ffa_frag_handle(ret);
	ASSERT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	ASSERT_NE(filler_handle, FFA_MEMORY_HANDLE_INVALID);

	send_fragmented_memory_region(
		&ret, &mb, filler_constituents, ARRAY_SIZE(filler_constituents),
		remaining_constituent_count, fragment_length, total_length,
		&filler_handle, FFA_MEMORY_HANDLE_ALLOCATOR_SPMC);

	/* Share the real (single-page) region with the SP. */
	ffa_memory_access_init(&receiver_v1_2, receiver_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);
	ffa_memory_region_init(
		mb.send, HF_MAILBOX_SIZE, sender_id, &receiver_v1_2, 1,
		sizeof(struct ffa_memory_access), real_constituents,
		ARRAY_SIZE(real_constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&total_length, &fragment_length);

	ret = ffa_mem_share(total_length, fragment_length);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	real_handle = ffa_mem_success_handle(ret);

	/*
	 * Ask the SP to retrieve the filler region (to dirty its RX), then
	 * the real region, and verify the SPMC zeroed the RX tail after
	 * writing the second retrieve response.
	 */
	ret = sp_check_retrieve_rx_tail_cmd_send(sender_id, receiver_id,
						 filler_handle, real_handle);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);
}
#endif /* RXTX_MAX_PAGE_COUNT > 1 */
