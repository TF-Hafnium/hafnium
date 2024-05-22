/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/mmu.h"
#include "hf/arch/types.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static uint8_t retrieve_buffer[PAGE_SIZE * 2];

static void memory_increment(struct ffa_memory_region *memory_region)
{
	size_t i;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_access *receiver =
		ffa_memory_region_get_receiver(memory_region, 0);
	uint8_t *ptr;
	enum ffa_memory_shareability shareability;
	enum ffa_memory_cacheability cacheability;

	composite = ffa_memory_region_get_composite(memory_region, 0);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;

	ASSERT_EQ(memory_region->receiver_count, 1);
	ASSERT_TRUE(receiver != NULL);
	ASSERT_NE(receiver->composite_memory_region_offset, 0);

	/*
	 * Validate retrieve response contains the memory attributes
	 * hafnium implements.
	 */
	shareability = memory_region->attributes.shareability;
	cacheability = memory_region->attributes.cacheability;
	ASSERT_EQ(shareability, FFA_MEMORY_INNER_SHAREABLE);
	ASSERT_EQ(cacheability, FFA_MEMORY_CACHE_WRITE_BACK);

	update_mm_security_state(composite, memory_region->attributes);

	/* Increment each byte of memory. */
	for (i = 0; i < PAGE_SIZE; ++i) {
		++ptr[i];
	}
}

void ffa_mem_retrieve_from_args(struct mailbox_buffers mb,
				void *retrieved_memory, ffa_id_t sender,
				ffa_memory_handle_t handle, uint32_t tag,
				ffa_memory_region_flags_t flags)
{
	uint32_t msg_size;

	msg_size = ffa_memory_retrieve_request_init_single_receiver(
		(struct ffa_memory_region *)mb.send, handle, sender,
		hf_vm_get_id(), tag, flags, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE, NULL);

	retrieve_memory(mb.recv, handle, retrieved_memory, HF_MAILBOX_SIZE,
			msg_size);
}

struct ffa_value sp_req_retrieve_cmd(ffa_id_t sender, uint32_t handle,
				     uint32_t tag, uint32_t flags,
				     struct mailbox_buffers mb)
{
	ffa_id_t own_id = hf_vm_get_id();

	ffa_mem_retrieve_from_args(mb, (void *)retrieve_buffer, sender, handle,
				   tag, flags);
	memory_increment((struct ffa_memory_region *)retrieve_buffer);

	/* Give the memory back and notify the sender. */
	ffa_mem_relinquish_init(mb.send, handle, 0, own_id);
	EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
	return sp_send_response(own_id, sender, 0);
}
