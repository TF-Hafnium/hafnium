/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * Vertical integration test: two secure partitions in the same SPMC
 * instance register RX/TX mailboxes of different sizes at the same time
 * (one 4 KiB, one the maximum multi-page size), and the SPMC must keep
 * their per-endpoint mailbox.buf_size separate while FF-A memory management
 * transactions (fragmented LEND, oversized retrieve responses) run against
 * each of them independently.
 *
 * Only meaningful when the SPMC is built with RXTX_MAX_PAGE_COUNT > 1
 * (e.g. the secure_aem_v8a_fvp_vhe build with plat_rxtx_max_page_count = 4).
 * In a single-page build both endpoints collapse to one page and the
 * scenario degenerates, so it is gated out.
 */
#if RXTX_MAX_PAGE_COUNT > 1

#define SMALL_MB_PAGES 1
#define LARGE_MB_PAGES FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT

/* The small-mailbox SP and the large-mailbox SP. */
#define SMALL_SP_ID SP_ID(1)
#define LARGE_SP_ID SP_ID(2)

/* Large enough that fragmented sharing takes at least three fragments. */
alignas(PAGE_SIZE) static uint8_t
	pages[FRAGMENTED_SHARE_PAGE_COUNT * PAGE_SIZE];

/*
 * Enough constituents that the first retrieve-response fragment for a single
 * fragment LEND exceeds one FF-A page (4 KiB), so only a receiver with a
 * multi-page mailbox can consume it without fragmenting.
 */
#define OVERSIZED_CONSTITUENT_COUNT \
	(FFA_PAGE_SIZE / sizeof(struct ffa_memory_region_constituent) + 8)

/*
 * Ask an SP to re-register its mailbox with the given page count, and
 * confirm it acknowledged the requested size.
 */
static void remap_sp_mailbox(ffa_id_t sp_id, uint32_t page_count)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res =
		sp_remap_mailbox_cmd_send(own_id, sp_id, page_count);

	ASSERT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	ASSERT_EQ(sp_resp(res), SP_SUCCESS);
	ASSERT_EQ(sp_resp_value(res), page_count);
}

/*
 * Set up the heterogeneous configuration: SMALL_SP keeps a single 4 KiB
 * page, LARGE_SP uses the maximum multi-page mailbox.
 */
static void set_up_heterogeneous_mailboxes(void)
{
	remap_sp_mailbox(SMALL_SP_ID, SMALL_MB_PAGES);
	remap_sp_mailbox(LARGE_SP_ID, LARGE_MB_PAGES);
}

/*
 * LEND `pages` to `receiver_id`, forcing the send to take three fragments
 * (see FRAGMENTED_SHARE_PAGE_COUNT), then have the SP retrieve it and
 * increment every byte. Verifies that a fragmented FFA_MEM_LEND completes
 * correctly regardless of the receiver's registered mailbox size.
 */
static void lend_fragmented_and_retrieve(void *send, size_t send_size,
					 ffa_id_t receiver_id)
{
	struct ffa_value ret;
	ffa_id_t sender_id = hf_vm_get_id();
	struct mailbox_buffers mb = (struct mailbox_buffers){
		.send = send,
		.recv = NULL,
		.buf_size = send_size,
	};
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 2},
		{.address = (uint64_t)pages + PAGE_SIZE * 3, .page_count = 1},
	};
	struct ffa_memory_access receiver_v1_2;
	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(receiver_id, receiver_id + 1);
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t handle;

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		pages[i] = i;
	}

	ffa_memory_access_init(&receiver_v1_2, receiver_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);

	remaining_constituent_count = ffa_memory_region_init(
		send, send_size, sender_id, &receiver_v1_2, 1,
		sizeof(struct ffa_memory_access), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&total_length, &fragment_length);

	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(total_length, fragment_length);

	/* Don't include the last constituent in the first fragment. */
	fragment_length -= sizeof(struct ffa_memory_region_constituent);
	remaining_constituent_count = 1;

	ret = ffa_mem_lend(total_length, fragment_length);
	handle = ffa_frag_handle(ret);
	ASSERT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	ASSERT_NE(handle, FFA_MEMORY_HANDLE_INVALID);

	send_fragmented_memory_region(
		&ret, &mb, constituents, ARRAY_SIZE(constituents),
		remaining_constituent_count, fragment_length, total_length,
		&handle, FFA_MEMORY_HANDLE_ALLOCATOR_SPMC);

	ret = sp_ffa_mem_lend_retrieve_cmd_send(sender_id, receiver_id, handle);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	ret = sp_increment_shared_buffer_cmd_send(sender_id, receiver_id);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	/*
	 * LEND revokes the sender's access until the receiver relinquishes
	 * and the sender reclaims the region.
	 */
	ret = sp_relinquish_shared_buffer_cmd_send(sender_id, receiver_id);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		uint8_t val = i + 1;
		ASSERT_EQ(pages[i], val);
	}
}

/*
 * Exercise a fragmented FFA_MEM_LEND against the small-mailbox SP and then
 * the large-mailbox SP, one after another. Each endpoint retrieves and
 * completes a multi-fragment transaction with its own registered mailbox
 * size, proving mailbox.buf_size is tracked independently per receiver
 * during actual memory-management data transfer, not just direct messages.
 */
TEST(ffa_mixed_mailbox, fragmented_lend_small_then_large_mailbox)
{
	struct mailbox_buffers mb = set_up_mailbox();

	set_up_heterogeneous_mailboxes();

	lend_fragmented_and_retrieve(mb.send, mb.buf_size, SMALL_SP_ID);
	lend_fragmented_and_retrieve(mb.send, mb.buf_size, LARGE_SP_ID);
}

/*
 * LEND a region with enough constituents that the retrieve response's first
 * fragment is bigger than one FF-A page (4 KiB), even though the send side
 * is still fragmented one page at a time. Only the large-mailbox SP can
 * consume such a response without needing FFA_MEM_FRAG_RX to continue.
 * This exercises the dynamic RXTX buffer size support end-to-end: the SPMC
 * must build (and the receiver must accept into its RX) a retrieve response
 * fragment sized against the receiver's actual buf_size rather than a single
 * hardcoded FF-A page.
 */
TEST(ffa_mixed_mailbox, oversized_retrieve_response_large_mailbox)
{
	struct ffa_value ret;
	ffa_id_t sender_id = hf_vm_get_id();
	static struct ffa_memory_region_constituent
		constituents[OVERSIZED_CONSTITUENT_COUNT];
	struct ffa_memory_access receiver_v1_2;
	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(LARGE_SP_ID, LARGE_SP_ID + 1);
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t handle;

	/*
	 * Give the primary a multi-page mailbox too, matching the receiver's
	 * setup. The send side must still be fragmented one FF-A page (4 KiB)
	 * at a time: Hafnium stores each fragment (initial and continuation)
	 * in a single page-sized pool entry regardless of the caller's own
	 * mailbox size. Only the retrieve *response*, sized against the
	 * large-mailbox SP's actual buf_size, is expected to exceed one page
	 * in a single fragment; that is what this test exercises.
	 */
	struct mailbox_buffers mb =
		set_up_mailbox_pages(FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT);
	struct mailbox_buffers send_mb = (struct mailbox_buffers){
		.send = mb.send,
		.recv = NULL,
		.buf_size = FFA_PAGE_SIZE,
	};

	set_up_heterogeneous_mailboxes();

	for (uint32_t i = 0; i < OVERSIZED_CONSTITUENT_COUNT; i++) {
		constituents[i].address = (uint64_t)pages + i * PAGE_SIZE;
		constituents[i].page_count = 1;
	}

	ffa_memory_access_init(&receiver_v1_2, LARGE_SP_ID, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);

	remaining_constituent_count = ffa_memory_region_init(
		mb.send, FFA_PAGE_SIZE, sender_id, &receiver_v1_2, 1,
		sizeof(struct ffa_memory_access), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NOT_SPECIFIED_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&total_length, &fragment_length);

	ASSERT_GT(remaining_constituent_count, 0);
	ASSERT_GT(total_length, FFA_PAGE_SIZE);

	ret = ffa_mem_lend(total_length, fragment_length);
	handle = ffa_frag_handle(ret);
	ASSERT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	ASSERT_NE(handle, FFA_MEMORY_HANDLE_INVALID);

	send_fragmented_memory_region(
		&ret, &send_mb, constituents, ARRAY_SIZE(constituents),
		remaining_constituent_count, fragment_length, total_length,
		&handle, FFA_MEMORY_HANDLE_ALLOCATOR_SPMC);

	ret = sp_ffa_mem_lend_retrieve_cmd_send(sender_id, LARGE_SP_ID, handle);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	/*
	 * Ensure the SP actually received the oversized response in a
	 * single fragment, rather than the SPMC fragmenting it and the SP's
	 * memory_region_desc_from_rx_fragments() helper transparently
	 * fetching the continuation via FFA_MEM_FRAG_RX. Without this check
	 * an SPMC bug that under-reports the SP's buf_size (e.g. treating a
	 * 16 KiB mailbox as 4 KiB) would go undetected: the retrieve would
	 * still complete successfully, just over several fragments instead
	 * of the single oversized one this test exists to exercise.
	 */
	EXPECT_EQ(sp_resp_value(ret), FFA_MEM_RETRIEVE_RESP_32);
	EXPECT_EQ(sp_resp_value2(ret), total_length);
}

#endif /* RXTX_MAX_PAGE_COUNT > 1 */
