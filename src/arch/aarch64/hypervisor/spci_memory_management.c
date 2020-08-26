/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/api.h"
#include "hf/dlog.h"
#include "hf/mpool.h"
#include "hf/panic.h"
#include "hf/spci_internal.h"
#include "hf/std.h"
#include "hf/check.h"

#include "smc.h"

extern uint8_t hv_rx[4096];
extern uint8_t hv_tx[4096];

#if SECURE_WORLD == 0
extern struct spinlock tx_lock;
#endif

struct handle_to_pointer {
	/* Owner vm_id. */
	/* exclusive or shared: at retrievve toggle to shared. at relinquish toggle to exclusive. */

	/* who was this shared with: to be checked int he retrieve. */

	handle_t handle;
	struct spci_memory_region *memory_region;
};

extern struct hv_buffers_t hypervisor_buffers;

#define HANDLE_MAP_SIZE 500
static struct handle_to_pointer handle_map[HANDLE_MAP_SIZE] = {{0}};
static struct handle_to_pointer
	handle_map_opposite_world[HANDLE_MAP_SIZE] = {{0}};

static bool map_entry_is_empty(const struct handle_to_pointer *map_entry)
{
	return map_entry->handle == 0;
}

static inline uint64_t get_constituent_addr(struct spci_memory_region_constituent *constituent)
{
	return ((uint64_t)constituent->address_high<<32) | constituent->address_low; 
}

static void spci_dbg_print_memory_region(struct spci_memory_region
	*memory_region, uint32_t handle)
{
	uint32_t constituent_count = memory_region->constituent_count;
	struct spci_memory_region_constituent *constituent = (
		struct spci_memory_region_constituent *)
		((uintptr_t)memory_region +memory_region->constituent_offset);

	for (int index = 0; index < constituent_count; index++)
	{
		dlog("handle %d constituent %#x\n", handle, get_constituent_addr(&constituent[index]));
	}
}

static struct spci_memory_region *get_memory_region(struct handle_to_pointer
	*selected_handler_map, uint32_t handle)
{
	if (selected_handler_map[(handle -1) & 0x7fffffff].handle == handle)
	{
		return selected_handler_map[(handle -1) & 0x7fffffff].memory_region;
	}

	return NULL;
}

#if SECURE_WORLD == 0
/* Store the handler in the internal data structure. */
static void store_handle(struct handle_to_pointer *map, handle_t handle,
			 struct spci_memory_region *memory_region)
{
	handle_t map_index;
	map_index = (handle -1) & 0x7fffffff;

	map[map_index].handle = handle;
	map[map_index].memory_region = memory_region;
}
#endif

bool allocate_handle(struct spci_memory_region *memory_region, handle_t *handle)
{
#if SECURE_WORLD
	*handle = 0;
#else
	*handle = 0x80000000;
#endif

	for (uint32_t map_index = 0; map_index < HANDLE_MAP_SIZE; map_index++) {
		if (map_entry_is_empty(&handle_map[map_index])) {
			*handle |= map_index + 1;

			handle_map[map_index].handle = *handle;
			handle_map[map_index].memory_region = memory_region;
			dlog("new handle %#x\n", *handle);
			return true;
		}
	}

	return false;
}

uint32_t get_memory_region_size(const struct spci_memory_region *memory_region)
{

	uint32_t constituent_count = memory_region->constituent_count;
	uint32_t receiver_count = memory_region->attribute_count;

	return constituent_count * sizeof(struct spci_memory_region_constituent) +
		sizeof(struct spci_memory_region_attributes) * receiver_count +
		sizeof(struct spci_memory_region);
}

struct mem_share_state {

	/* The memory region being shared. */
	struct spci_memory_region *memory_region;

	/* The size of the region pointer to by memory_region. */
	uint32_t full_region_size;

	/* Keeps track of the ammount of data filled in the memory region. */
	uint32_t filled_data_size;

	/* globally unique handle un-ambiguously referring to the memory region. */
	uint32_t handle;
};

struct mem_retrieve_state {

	struct spci_memory_region *memory_region;
	uint32_t handle;
	uint32_t filled_constituent;
};

#define SHARE_STATE_MAX 5
/*
 * An array storing the state of multi-fragment memory shares.
 *
 * XXX: This should probably be an extensible data structure.
 */
static struct mem_share_state share_state[SHARE_STATE_MAX];

/*
 * An array storing the state of multi-fragment memory retrieves.
 *
 * XXX: This should probably be an extensible data structure.
 */
static struct mem_retrieve_state retrieve_state[SHARE_STATE_MAX];
static struct spinlock retrieve_lock = {.v=0};

struct spci_value spci_mem_share_internal(
	uint64_t base_addr, uint32_t page_count, uint32_t fragment_len,
	uint32_t length, uint32_t cookie, struct vm *from_vm,
	struct mpool *page_pool, bool world_switched)
{
	uint32_t receiver_count;
	uint32_t constituent_count;
	uint32_t memory_region_size;
	bool world_change_required = false;

	handle_t handle;

#if SECURE_WORLD == 0
	struct spci_value smc_res;
#endif

	const struct spci_memory_region *rx_memory_region;
	struct spci_memory_region *memory_region_copy = NULL;
	void *offsetted_region_copy;

	uint32_t filled_data_size = 0;
	struct mpool local_page_pool;

	mpool_init_with_fallback(&local_page_pool, page_pool);


	if (!base_addr) {
		/* TX based memory share. */

#if !SECURE_WORLD
		rx_memory_region = from_vm->mailbox.send;
#else
		rx_memory_region = (struct spci_memory_region *)hypervisor_buffers.tx;
#endif

	} else {
		/* The memory region description is in a page pointed to by
		 * base_addr. */
		/* Panic for now as we are missing an implementation. */
		panic("The SPCI_MEM_SHARE implementation does not support "
		      "passing the memory region description on a separate "
		      "page\n");
	}


	dlog("---Mem_share_invocation-- page_count %d, fragment_len %d, length %d, cookie %d\n", page_count, fragment_len, length, cookie);
	// first invocation of a multi-fragment mem-copy has length != 0.
	if(length != 0)
	{
		memory_region_copy = mpool_alloc_contiguous(
			&local_page_pool, ((length - 1)/ SPCI_PAGE_SIZE) + 1, 1);

		if (!memory_region_copy) {
			dlog("Failed to allocate required memory for "
				 "SPCI_MEM_SHARE.\n");
			return (struct spci_value){
				SPCI_ERROR_32, 0, SPCI_NO_MEMORY, 0, 0, 0, 0, 0};
		}

		dlog("---Mem_share_invocation-- region address %#X \n", memory_region_copy);
		offsetted_region_copy = memory_region_copy;
		memory_region_size = (((length  -1) / SPCI_PAGE_SIZE) + 1)*SPCI_PAGE_SIZE;

		if(cookie)
		{
			CHECK(fragment_len != length);
			CHECK(cookie < SHARE_STATE_MAX);
			CHECK(share_state[cookie].memory_region == NULL);

			share_state[cookie].memory_region = memory_region_copy;
			share_state[cookie].full_region_size = length;
			share_state[cookie].filled_data_size = 0;
		}
	}
	else
	{

		// In a multi-fragment scenario the cookie must be non-zero.
		CHECK(cookie != 0);

		/* if fragment_len == 0 this is multifragment call. */
		/*
		 * Obtain the pointer to the partial fragmented memory share operation.
		 */
		struct mem_share_state *cur_share_state = &share_state[cookie];
		CHECK(cur_share_state);

		filled_data_size = cur_share_state->filled_data_size;

		/*
		 * set the memory pointer to the first unfilled byte in the partial transfer.
		 */
		offsetted_region_copy = (struct spci_memory_region *)
			(((uintptr_t)cur_share_state->memory_region) + filled_data_size);

		memory_region_copy = cur_share_state->memory_region;

		CHECK(filled_data_size + fragment_len <=  cur_share_state->full_region_size);

		memory_region_size = cur_share_state->full_region_size;
	}



	memcpy_s(offsetted_region_copy, memory_region_size - filled_data_size, rx_memory_region,
		 fragment_len);

	if (cookie != 0)
	{
		struct mem_share_state *cur_state = &share_state[cookie];

		cur_state->filled_data_size += fragment_len;
		filled_data_size = cur_state->filled_data_size;

	}

	receiver_count = memory_region_copy->attribute_count;
	constituent_count = memory_region_copy->constituent_count;

	for (uint32_t attribute_index = 0; attribute_index < receiver_count;
	     attribute_index++)
	{
		spci_vm_id_t receiver_vm_id;
		if (cookie) {
			receiver_vm_id =
				share_state[cookie].memory_region->attributes[attribute_index].receiver;
		} else {
			receiver_vm_id =
				rx_memory_region->attributes[attribute_index].receiver;
		}

#if SECURE_WORLD
		world_change_required = !(0x8000 & receiver_vm_id);
#else
		world_change_required = (0x8000 & receiver_vm_id);
#endif

	}

	if (world_change_required && (!world_switched)) {
# if SECURE_WORLD
	panic("We should not be here in the secure_world.\n");
#else
		/* Write the region descriptor onto Hf's Tx buffer. */
		sl_lock(&tx_lock);
		memcpy_s(hv_tx, 4096, offsetted_region_copy, fragment_len);

		/* This receiver is in the Secure side. */
		smc_res = smc64(SPCI_MEM_SHARE_64, base_addr, page_count,
				fragment_len, length, cookie, 0, 0);
		sl_unlock(&tx_lock);
		if (smc_res.func == SPCI_ERROR_32) {
			mpool_add_chunk(&local_page_pool, memory_region_copy,
					memory_region_size);

			mpool_fini(&local_page_pool);
			return smc_res;
		}
		handle = smc_res.arg2;

		if (length != 0) {
			if(cookie) {
				share_state[cookie].handle = handle;
			}

			store_handle(handle_map_opposite_world, handle,
					 memory_region_copy);
		}
#endif
	} else {
		/*
		 * Either the memory is only shared within the same world or we are
		 * in the opposite side to the sharing VM.
		 */

		if (length != 0) {
			if (!allocate_handle(memory_region_copy, &handle)) {
				/* Failed to store the handle. Free memory. */
				mpool_add_chunk(&local_page_pool, memory_region_copy,
						memory_region_size);

				mpool_fini(&local_page_pool);
				return (struct spci_value){SPCI_ERROR_32,
							   0,
							   SPCI_NO_MEMORY,
							   0,
							   0,
							   0,
							   0,
							   0};
			}

			share_state[cookie].handle = handle;

		} else {
			CHECK(cookie != 0);
			/* multi-fragment secondary invocation, do not allocate handle */
			handle = share_state[cookie].handle;
		}

		spci_dbg_print_memory_region(memory_region_copy, handle);
	}
	if (cookie != 0)
	{
		if(memory_region_size == filled_data_size)
		{
			share_state[cookie].memory_region = NULL;
		}
	}
	mpool_fini(&local_page_pool);
	return (struct spci_value){SPCI_SUCCESS_32, 0, handle, 0, 0, 0, 0, 0};
}

static inline struct spci_memory_region_constituent *get_constituents(struct spci_memory_region *memory_region)
{
	return (struct spci_memory_region_constituent *)
		(((uintptr_t) memory_region) + memory_region->constituent_offset);
}

/**
 * Create the S2 mappings.
 */
static bool spci_map_region_s2(struct spci_memory_region *memory_region,
	struct vm *from_vm, struct mpool *page_pool)
{
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count = memory_region->constituent_count;
	uint16_t spci_attributes;
	uint32_t hafnium_attributes;

	struct mpool local_page_pool;

	struct vm_locked vm_locked = vm_lock(from_vm);

	constituents = get_constituents(memory_region);

	mpool_init_with_fallback(&local_page_pool, page_pool);

	/* Find the attributes with which to map the pages on the caller VM. */
	for (uint32_t index = 0; index < memory_region->attribute_count; index++)
	{
		if (memory_region->attributes[index].receiver == from_vm->id)
		{
			hafnium_attributes = MM_MODE_UNOWNED | MM_MODE_SHARED;

			spci_attributes =
				memory_region->attributes[index].memory_attributes;
			switch ((spci_attributes>>5) & 3)
			{
			case 0:
				hafnium_attributes |= MM_MODE_R;
				break;

			case 1:
				hafnium_attributes |= MM_MODE_R | MM_MODE_X;
				break;

			case 2:
				hafnium_attributes |= MM_MODE_R | MM_MODE_W;
				break;
			}
		}
	}

	dlog("\nset S2 start\n");
	for (uint32_t index = 0; index < constituent_count; index++)
	{
		uint32_t page_count = constituents[index].page_count;

		for (uint32_t page_num = 0; page_num < page_count; page_num++)
		{
			uintptr_t address = get_constituent_addr(&constituents[index]) + SPCI_PAGE_SIZE
				* page_num;

			dlog("set S2 %#x address %#x\n", from_vm->id, address);

			/* Map page on the pages on the retrieve caller. */
			if(!mm_vm_identity_map(&vm_locked.vm->ptable, pa_init(address),
				pa_init(address + SPCI_PAGE_SIZE),
				hafnium_attributes, &local_page_pool,
				NULL))
			{
				dlog("failed to set S2 mappings\n");
				return false;
			}
		}
	}
	dlog("set S2 end\n\n");

	mpool_fini(&local_page_pool);
	vm_unlock(&vm_locked);
	return true;
}

#define MAX_COOKIE 10
static bool cookie_tracker[MAX_COOKIE] = {0};

/**
 * Obtain a unique cookie to be used in the retrieve operations.
 * Must only be called with retrieve_lock acquired.
 *
 * A 0 return signals failure.
 */
static inline uint32_t get_retrieve_cookie()
{

	uint32_t index;

	for (index=0; index<MAX_COOKIE; index++)
	{
		if (cookie_tracker[index] == 0)	{
			cookie_tracker[index] = 1;
			return index+1;
		}
	}

	return 0;
}

/**
 * Put a unique cookie used for retrieve operations.
 */
static inline bool put_retrieve_cookie(uint32_t cookie)
{

	if (cookie_tracker[cookie] == 1)
	{
		dlog("Tried to erroneously put cookie %d\n", cookie);
		return false;
	}

	cookie_tracker[cookie] = 0;

	return true;
}

struct spci_value spci_mem_retrieve_req_internal(
	uint64_t base_addr, uint32_t page_count, uint32_t fragment_count,
	uint32_t length, uint32_t cookie, struct vm *from_vm,
	struct mpool *page_pool, bool world_changed)
{
	uint32_t handle;
	bool handle_alloc_opposite;
	struct handle_to_pointer *selected_handler_map;
	uint32_t constituent_count;
	struct spci_memory_region *mem_region;
	struct spci_memory_region_constituent *constituent_dst;
	struct spci_memory_region_constituent *constituent_src;
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t index;

	struct spci_retrieve_descriptor *retrieve_mem_descriptor;

	/* Obtain the handle from the Rx buffer of the caller VM. */
	handle = ((struct mem_retrieve_descriptor *)from_vm->mailbox.send)->handle;

#if SECURE_WORLD == 1
	handle_alloc_opposite = (0x80000000 & handle);
#else
	/* Normal world. */
	handle_alloc_opposite = !(0x80000000 & handle);
#endif

	if (handle_alloc_opposite)
	{
		selected_handler_map = handle_map_opposite_world;
	}
	else
	{
		selected_handler_map = handle_map;
	}

	CHECK((handle & 0x7fffffff) < HANDLE_MAP_SIZE);
	mem_region = get_memory_region(selected_handler_map, handle);
	if (mem_region)
	{
		/* TODO: Acquire vm lock. */
		/* Found the handle, implement the the S-2 mappings. */
		if(!spci_map_region_s2(mem_region, from_vm, page_pool))
		{
			return spci_error(SPCI_NO_MEMORY);
		}

		/* TODO: Release vm lock. */
	}
	else
	{
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	constituent_src = spci_memory_region_get_constituents(mem_region);

	constituent_count = mem_region->constituent_count;
	total_length = constituent_count * sizeof(struct spci_memory_region_constituent)
		 + sizeof(struct spci_retrieve_descriptor);

	retrieve_mem_descriptor =
		(struct spci_retrieve_descriptor *)from_vm->mailbox.recv;

	retrieve_mem_descriptor->constituent_count = constituent_count;

	constituent_dst = retrieve_mem_descriptor->constituents;

	retrieve_mem_descriptor->page_count = 0;
	for (index = 0; index < constituent_count; index++)
	{
		uint32_t pcount = constituent_src[index].page_count;

		constituent_dst[index].address_low = constituent_src[index].address_low;
		constituent_dst[index].address_high = constituent_src[index].address_high;
		constituent_dst[index].page_count = pcount;

		retrieve_mem_descriptor->page_count += pcount;

		if (((uintptr_t)&constituent_dst[index+1]) -
			(uintptr_t)retrieve_mem_descriptor >= SPCI_PAGE_SIZE) {

			sl_lock(&retrieve_lock);
			cookie = get_retrieve_cookie();

			retrieve_state[cookie].handle = handle;
			retrieve_state[cookie].memory_region = mem_region;
			retrieve_state[cookie].filled_constituent = index+1;

			sl_unlock(&retrieve_lock);

			return (struct spci_value)
				{SPCI_MEM_RETRIEVE_RESP_32, 0, 0, SPCI_PAGE_SIZE, total_length, cookie, 0, 0};
			break;
		}
	}
	fragment_length = index * sizeof(struct spci_memory_region_constituent)
		 + sizeof(struct spci_retrieve_descriptor);

	dlog("end retrieve\n");
	return (struct spci_value)
		{SPCI_MEM_RETRIEVE_RESP_32, 0, 0, fragment_length, total_length, cookie, 0, 0};
}

struct spci_value spci_mem_op_resume_internal (uint32_t cookie, struct vm* from_vm)
{
	CHECK(cookie);
	CHECK(retrieve_state[cookie].memory_region);

	uint32_t *filled_constituent = &retrieve_state[cookie].filled_constituent;
	uint32_t total_constituent = retrieve_state[cookie].memory_region->constituent_count;

	struct spci_memory_region_constituent *constituent_dst =
		(struct spci_memory_region_constituent *)from_vm->mailbox.recv;

	struct spci_memory_region_constituent *constituent_src =
		&get_constituents(retrieve_state[cookie].memory_region)[*filled_constituent];

	uint32_t constituent_count =
		total_constituent - *filled_constituent;

	uint32_t max_frag_c_count = SPCI_PAGE_SIZE/sizeof(struct spci_memory_region_constituent);
	uint32_t frag_size;

	dlog("mem op resume\n");
	constituent_count = constituent_count < max_frag_c_count ? constituent_count: max_frag_c_count;
	frag_size = constituent_count * sizeof(struct spci_memory_region_constituent);

	for (uint32_t index = 0; index < constituent_count; index++)
	{
		constituent_dst[index].address_low = constituent_src[index].address_low;
		constituent_dst[index].address_high = constituent_src[index].address_high;
		constituent_dst[index].page_count = constituent_src[index].page_count;
	}
	*filled_constituent += constituent_count;

	if (total_constituent == *filled_constituent) {

		sl_lock(&retrieve_lock);

		retrieve_state[cookie].handle = 0;
		retrieve_state[cookie].memory_region = NULL;
		*filled_constituent = 0;

		put_retrieve_cookie(cookie);

		sl_unlock(&retrieve_lock);
	}

	dlog("mem op resume end\n");
	return (struct spci_value)
		{SPCI_MEM_RETRIEVE_RESP_32, 0, 0, frag_size, 0, cookie, 0, 0};
}


struct spci_value spci_memory_relinquish(struct mem_relinquish_descriptor *relinquish_desc,
	struct mpool *page_pool, struct vm *from_vm)
{
	uint32_t handle;
	uint32_t map_index;
	bool opposite_world_map;
	struct handle_to_pointer *selected_handler_map;
	struct mpool local_page_pool;
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count;
	struct spci_memory_region *memory_region;

	struct vm_locked vm_locked = vm_lock(from_vm);

	mpool_init_with_fallback(&local_page_pool, page_pool);

	/* Obtain the handle from the Rx buffer of the caller VM. */
	handle = relinquish_desc->handle;

#if SECURE_WORLD == 1
	opposite_world_map = (0x80000000 & handle);
#else
	/* Normal world. */
	opposite_world_map  = !(0x80000000 & handle);
#endif
	if (opposite_world_map)
	{
		selected_handler_map = handle_map_opposite_world;
	}
	else
	{
		selected_handler_map = handle_map;
	}

	map_index = (handle -1) & 0x7fffffff;

	CHECK(selected_handler_map[map_index].handle == handle);

	memory_region = selected_handler_map[map_index].memory_region;
	constituents = get_constituents(memory_region);
	constituent_count = memory_region->constituent_count;

	dlog("\nrelinquish S2 relinquish handle %d\n", handle);
	for (uint32_t index = 0; index < constituent_count; index++)
	{
		uint32_t page_count = constituents[index].page_count;

		for (uint32_t page_num = 0; page_num < page_count; page_num++)
		{
#if SECURE_WORLD == 1
			uintptr_t address = get_constituent_addr(&constituents[index]) + SPCI_PAGE_SIZE
				* page_num;

			dlog("relinquish S2 %#X address %#x\n", from_vm->id, address);
			/* Map page on the pages on the retrieve caller. */
			mm_vm_unmap(&vm_locked.vm->ptable, pa_init(address),
				pa_init(address + SPCI_PAGE_SIZE), &local_page_pool);
#endif
		}
	}
	dlog("relinquish S2 end\n\n");

	mpool_fini(&local_page_pool);
	vm_unlock(&vm_locked);
	return (struct spci_value){.func = SPCI_SUCCESS_32};
}

struct spci_value spci_memory_reclaim(handle_t handle, uint32_t flags,
	struct vm* current_vm, struct mpool *page_pool)
{
	uint32_t map_index;
	struct spci_memory_region *memory_region;
	bool opposite_world_map;
	struct handle_to_pointer *selected_handler_map;
	struct mpool local_page_pool;

	mpool_init_with_fallback(&local_page_pool, page_pool);

#if SECURE_WORLD == 1
	opposite_world_map  = (0x80000000 & handle);
#else
	/* Normal world. */
	opposite_world_map  = !(0x80000000 & handle);
#endif
	if (opposite_world_map)
	{
		selected_handler_map = handle_map_opposite_world;
	}
	else
	{
		selected_handler_map = handle_map;
	}
	/*
	 * unmap the memory region defined by the handle from the caller VM S2
	 * mapping.
	 */
	map_index = (handle -1) & 0x7fffffff;

	CHECK(selected_handler_map[map_index].handle == handle);

	memory_region = selected_handler_map[map_index].memory_region;

	dlog("reclaim start\n");
	spci_dbg_print_memory_region(memory_region, handle);
	dlog("reclaim end\n");

	if (!mpool_add_chunk(&local_page_pool, memory_region,
		((get_memory_region_size(memory_region) / SPCI_PAGE_SIZE) + 1) * SPCI_PAGE_SIZE))
	{
		panic("free memory region pages failed\n");
	}
	/* Make sure we release the freed memory back to the main memory pool. */
	mpool_fini(&local_page_pool);

	selected_handler_map[map_index].handle = 0;
	selected_handler_map[map_index].memory_region = NULL;


	//XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	//
	// Missing S2 unmmapping code.
	//
	//XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX

	return (struct spci_value){.func = SPCI_SUCCESS_32};
}
