/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/mm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t pages[4 * PAGE_SIZE];

static ffa_memory_handle_t init_and_send(
	struct mailbox_buffers mb,
	struct ffa_memory_region_constituent constituents[],
	size_t constituents_count)
{
	uint32_t total_length;
	uint32_t fragment_length;
	struct ffa_value ret;
	ffa_memory_handle_t handle;

	EXPECT_EQ(ffa_memory_region_init(
			  mb.send, HF_MAILBOX_SIZE, HF_PRIMARY_VM_ID,
			  HF_TEE_VM_ID, constituents, constituents_count, 0, 0,
			  FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_OUTER_SHAREABLE, &total_length,
			  &fragment_length),
		  0);
	EXPECT_EQ(total_length, fragment_length);
	ret = ffa_mem_share(total_length, fragment_length);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);
	dlog("Got handle %#x.\n", handle);
	EXPECT_NE(handle, 0);
	EXPECT_NE(handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK,
		  FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR);

	return handle;
}

TEAR_DOWN(trusty)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Memory can be shared to Trusty via the Trusty SPD in TF-A. (Trusty itself
 * never actually retrieves it in these tests, we're just testing the FF-A
 * interface between Hafnium and the Trusty SPD.)
 */
TEST(trusty, memory_share)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Dirty the memory before sharing it. */
	memset_s(pages, sizeof(pages), 'b', PAGE_SIZE);

	init_and_send(mb, constituents, ARRAY_SIZE(constituents));

	/* Make sure we can still write to it. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		pages[i] = i;
	}
}

/**
 * Multiple memory regions can be sent without blocking.
 */
TEST(trusty, share_twice)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	init_and_send(mb, constituents, ARRAY_SIZE(constituents));

	/* Share another page. */
	constituents[0].address = (uint64_t)pages + PAGE_SIZE;
	init_and_send(mb, constituents, ARRAY_SIZE(constituents));
}

/*
 * Memory which wasn't shared can't be reclaimed.
 */
TEST(trusty, memory_reclaim_invalid)
{
	ffa_memory_handle_t invalid_handle = 42;
	struct ffa_value ret;

	ret = ffa_mem_reclaim(invalid_handle, 0);

	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

/**
 * Memory which was shared can be immediately reclaimed.
 */
TEST(trusty, memory_reclaim)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	uint8_t *ptr = pages;
	ffa_memory_handle_t handle;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};

	/* Dirty the memory before sharing it. */
	memset_s(ptr, sizeof(pages), 'b', PAGE_SIZE);

	handle = init_and_send(mb, constituents, ARRAY_SIZE(constituents));

	/* Make sure we can still write to it. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		pages[i] = i;
	}

	dlog("Reclaiming handle %#x.\n", handle);
	ret = ffa_mem_reclaim(handle, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}
