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

static struct spinlock mem_region_lock = {.v=0};
static uint64_t handle_counter = 0;

struct handle_to_pointer {
	/* Owner vm_id. */
	/* exclusive or shared: at retrievve toggle to shared. at relinquish toggle to exclusive. */

	/* who was this shared with: to be checked int he retrieve. */

	handle_t handle;
	struct spci_memory_region *memory_region;

	uint32_t filled_offset;
	uint32_t transmitted_offset;
	uint32_t size;
	bool is_fully_described;
};

extern struct hv_buffers_t hypervisor_buffers;

#define HANDLE_MAP_SIZE 500
static struct handle_to_pointer handle_map[HANDLE_MAP_SIZE] = {{0}};

static inline uint64_t get_constituent_addr(struct spci_memory_region_constituent *constituent)
{
	return constituent->address;
}

static void spci_dbg_print_memory_region(struct spci_memory_region
	*memory_region, uint32_t handle)
{
	struct spci_composite_memory_region *composite =
		spci_memory_region_get_composite(memory_region);

	uint32_t constituent_count = composite->constituent_count;
	struct spci_memory_region_constituent *constituent =
		spci_memory_region_get_constituents(memory_region);

	for (int index = 0; index < constituent_count; index++)
	{
		dlog("handle %d constituent %#x\n", handle, get_constituent_addr(&constituent[index]));
	}
}

uint32_t get_memory_region_size(const struct spci_memory_region *memory_region)
{
	struct spci_composite_memory_region *composite =
		spci_memory_region_get_composite(memory_region);

	uint32_t constituent_count = composite->constituent_count;
	uint32_t receiver_count = memory_region->endpoint_count;

	return constituent_count * sizeof(struct spci_memory_region_constituent) +
		sizeof(struct spci_composite_memory_region) +
		sizeof(struct spci_endpoint_memory_access) * receiver_count +
		sizeof(struct spci_memory_region);
}

/* Store the handler in the internal data structure. */
static void store_handle(handle_t handle,
			 struct spci_memory_region *memory_region, uint32_t total_size, uint32_t filled_size)
{
	sl_lock(&mem_region_lock);

	for(uint32_t i = 0; i < HANDLE_MAP_SIZE; i++)
	{
		if(handle_map[i].memory_region == NULL)
		{
			handle_map[i].handle = handle;
			handle_map[i].memory_region = memory_region;
			handle_map[i].size = total_size;
			handle_map[i].filled_offset = filled_size;

			sl_unlock(&mem_region_lock);
			return;
		}
	}

	panic("-- cannot find free map entry\n");
	sl_unlock(&mem_region_lock);
}

static struct handle_to_pointer *fetch_handle_entry(handle_t handle)
{
	for(uint32_t i = 0; i < HANDLE_MAP_SIZE; i++)
	{
		if(handle_map[i].handle == handle)
		{
			return &handle_map[i];
		}
	}
	panic("failed to fetch handle to pointer info associated with handle %d\n", handle);
	return NULL;
}

static struct spci_memory_region *fetch_region(handle_t handle)
{
	struct handle_to_pointer *h_to_p;

	sl_lock(&mem_region_lock);
	h_to_p = fetch_handle_entry(handle);
	sl_unlock(&mem_region_lock);

	if(h_to_p)
	{
		CHECK(h_to_p->memory_region);
		return h_to_p->memory_region;
	}

	panic("failed to fetch the memory region assoc with handle %d\n", handle);

	return NULL;
}

static bool erase_region(handle_t handle, struct mpool *local_page_pool)
{
	struct handle_to_pointer *h_to_p;
	struct spci_memory_region *memory_region;

	sl_lock(&mem_region_lock);
	h_to_p = fetch_handle_entry(handle);
	memory_region = h_to_p->memory_region;

	if (false){
		dlog("begin erasing memory region %d\n", handle);
		spci_dbg_print_memory_region(memory_region, handle);
		dlog("end erasing memory region\n");
	}

	if (!mpool_add_chunk(local_page_pool, memory_region,
		((get_memory_region_size(memory_region) / SPCI_PAGE_SIZE) + 1) * SPCI_PAGE_SIZE))
	{
		panic("free memory region pages failed\n");
	}


	h_to_p->handle = 0;
	h_to_p->memory_region = NULL;
	h_to_p->filled_offset = 0;
	h_to_p->is_fully_described = false;
	h_to_p->size = 0;

	sl_unlock(&mem_region_lock);

	return true;
}

bool allocate_handle(struct spci_memory_region *memory_region, handle_t *handle)
{

	*handle = ++handle_counter;

#if SECURE_WORLD == 0
	*handle |= 0x80000000;
#endif

	return true;
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
 * An array storing the state of multi-fragment memory retrieves.
 *
 * XXX: This should probably be an extensible data structure.
 */
static struct mem_retrieve_state retrieve_state[SHARE_STATE_MAX];
static struct spinlock retrieve_lock = {.v=0};

struct spci_value spci_mem_share_internal(
	uint32_t length, uint32_t frag_len,
	uint64_t base_addr, uint32_t page_count, struct vm *from_vm,
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

	memory_region_copy = mpool_alloc_contiguous(
		&local_page_pool, ((length - 1)/ SPCI_PAGE_SIZE) + 1, 1);

	if (!memory_region_copy) {
		dlog("Failed to allocate required memory for "
			 "SPCI_MEM_SHARE.\n");
		return (struct spci_value){
			SPCI_ERROR_32, 0, SPCI_NO_MEMORY, 0, 0, 0, 0, 0};
	}

	offsetted_region_copy = memory_region_copy;
	memory_region_size = (((length  -1) / SPCI_PAGE_SIZE) + 1)*SPCI_PAGE_SIZE;


	memcpy_s(memory_region_copy, memory_region_size - filled_data_size, rx_memory_region,
		 frag_len);


	receiver_count = memory_region_copy->endpoint_count;
	constituent_count = spci_memory_region_get_composite(memory_region_copy)->constituent_count;

	for (uint32_t attribute_index = 0; attribute_index < receiver_count;
	     attribute_index++)
	{
		spci_vm_id_t receiver_vm_id;
		receiver_vm_id =
			rx_memory_region->endpoint_access[attribute_index].receiver;

#if SECURE_WORLD
		world_change_required = world_change_required || !(0x8000 & receiver_vm_id);
#else
		world_change_required = world_change_required || (0x8000 & receiver_vm_id);
#endif

	}

	if (world_change_required && (!world_switched)) {
# if SECURE_WORLD
	panic("We should not be here in the secure_world.\n");
#else
		/* Write the region descriptor onto Hf's Tx buffer. */
		sl_lock(&tx_lock);
		memcpy_s(hv_tx, 4096, offsetted_region_copy, frag_len);

		/* This receiver is in the Secure side. */
		smc_res = smc64(SPCI_MEM_SHARE_64, length, frag_len,
			base_addr, page_count, 0, 0, 0);

		sl_unlock(&tx_lock);
		if (smc_res.func == SPCI_ERROR_32) {
			mpool_add_chunk(&local_page_pool, memory_region_copy,
					memory_region_size);

			mpool_fini(&local_page_pool);
			return smc_res;
		}
		handle = smc_res.arg3<<32 | smc_res.arg2;

		store_handle(handle, memory_region_copy, length, frag_len);
#endif
	} else {
		/*
		 * Either the memory is only shared within the same world or we are
		 * in the opposite side to the sharing VM.
		 */

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

		if (false) {
			spci_dbg_print_memory_region(memory_region_copy, handle);
		}

		store_handle(handle, memory_region_copy, length, frag_len);
	}

	mpool_fini(&local_page_pool);

	return (struct spci_value){SPCI_SUCCESS_32, 0, handle & 0xffffffff , handle>>32, 0, 0, 0, 0};
}

struct spci_value spci_mem_frag_tx(uint32_t handle_low,
	uint32_t handle_high, uint32_t frag_len, uint32_t agg_sender_id,
	struct vm *from_vm)
{
	const struct spci_memory_region *rx_memory_region;
	handle_t handle = (handle_t)handle_high<<32 | handle_low;

	struct spci_memory_region *memory_region;
	struct handle_to_pointer *h_to_p;
	void *region_to_fill;

	sl_lock(&mem_region_lock);
	h_to_p = fetch_handle_entry(handle);

	memory_region = h_to_p->memory_region;

	if (frag_len > h_to_p->size - h_to_p->filled_offset)
	{
		dlog("--------frag_tx failed\n");
		sl_unlock(&mem_region_lock);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

#if !SECURE_WORLD
	rx_memory_region = from_vm->mailbox.send;
#else
	rx_memory_region = (struct spci_memory_region *)hypervisor_buffers.tx;
#endif

	region_to_fill = (void*)((uintptr_t)memory_region + (uintptr_t)h_to_p->filled_offset);
	memcpy_s(region_to_fill, frag_len, rx_memory_region,
		 frag_len);

	h_to_p->filled_offset += frag_len;

	sl_unlock(&mem_region_lock);

#if !SECURE_WORLD

	/* Fill in the information in the Hv Tx buffer. */
	memcpy_s(hv_tx, frag_len, rx_memory_region, frag_len);

	if (false) {
		spci_dbg_print_memory_region(memory_region, handle);
	}

	return smc32(SPCI_MEM_FRAG_TX_32, handle_low,
		handle_high, frag_len, agg_sender_id, 0, 0, 0);
#endif

	return (struct spci_value){SPCI_MEM_FRAG_RX_32, handle_low,
		handle_high, h_to_p->filled_offset, agg_sender_id, 0, 0, 0};
}

struct spci_value spci_mem_frag_rx(uint32_t handle_low,
	uint32_t handle_high, uint32_t frag_offset, uint32_t agg_sender_id, struct vm *from_vm)
{
	const struct spci_memory_region *tx_memory_region;
	handle_t handle = (handle_t)handle_high<<32 | handle_low;

	struct spci_memory_region *memory_region;
	struct handle_to_pointer *h_to_p;
	void *region_offset;

	sl_lock(&mem_region_lock);
	h_to_p = fetch_handle_entry(handle);

	memory_region = h_to_p->memory_region;

	if (frag_offset > h_to_p->size - h_to_p->transmitted_offset)
	{
		dlog("frag_rx failed\n");
		sl_unlock(&mem_region_lock);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

#if !SECURE_WORLD
	tx_memory_region = from_vm->mailbox.recv;
#else
	tx_memory_region = (struct spci_memory_region *)hypervisor_buffers.rx;
#endif

	region_offset = (void*)((uintptr_t)memory_region + (uintptr_t)h_to_p->transmitted_offset);
	memcpy_s((void *) tx_memory_region, frag_offset, region_offset,
		 frag_offset);

	h_to_p->transmitted_offset += frag_offset;

	sl_unlock(&mem_region_lock);

#if !SECURE_WORLD

	/* Fill in the information in the Hv Rx buffer. */
	memcpy_s(hv_rx, frag_offset, tx_memory_region, frag_offset);

	if (false) {
		dlog("begin frag_rx\n");
		spci_dbg_print_memory_region(memory_region, handle);
		dlog("end frag_rx\n");
	}

	return smc32(SPCI_MEM_FRAG_TX_32, handle_low,
		handle_high, frag_offset, agg_sender_id, 0, 0, 0);
#endif

	return (struct spci_value){SPCI_MEM_FRAG_TX_32, handle_low,
		handle_high, h_to_p->transmitted_offset, agg_sender_id, 0, 0, 0};
}

/**
 * Create the S2 mappings.
 */
static bool spci_map_region_s2(struct spci_memory_region *memory_region,
	struct vm *from_vm, struct mpool *page_pool)
{
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count = spci_memory_region_get_composite(memory_region)->constituent_count;;
	uint16_t spci_attributes;
	uint32_t hafnium_attributes;

	struct mpool local_page_pool;

	struct vm_locked vm_locked = vm_lock(from_vm);

	constituents = spci_memory_region_get_constituents(memory_region);

	mpool_init_with_fallback(&local_page_pool, page_pool);

	/* Find the attributes with which to map the pages on the caller VM. */
	for (uint32_t index = 0; index < memory_region->endpoint_count; index++)
	{
		if (memory_region->endpoint_access[index].receiver == from_vm->id)
		{
			hafnium_attributes = MM_MODE_UNOWNED | MM_MODE_SHARED;

			spci_attributes =
				memory_region->endpoint_access[index].memory_permission;
			switch ((spci_attributes) & 3)
			{
			case 0:
				panic("un-allowed state\n");
				break;

			case 1:
				hafnium_attributes |= MM_MODE_R;
				break;

			case 2:
				hafnium_attributes |= MM_MODE_R | MM_MODE_W;
				break;
			case 3:
				panic("un-allowed state\n");
			}
			switch ((spci_attributes>>2) & 3)
			{
			case 0:
				panic("un-allowed state\n");
				break;

			case 1:
				break;

			case 2:
				hafnium_attributes |= MM_MODE_X;
				break;
			case 3:
				panic("un-allowed state\n");
				break;
			}
		}
	}

	for (uint32_t index = 0; index < constituent_count; index++)
	{
		uint32_t page_count = constituents[index].page_count;

		for (uint32_t page_num = 0; page_num < page_count; page_num++)
		{
			uintptr_t address = get_constituent_addr(&constituents[index]) + SPCI_PAGE_SIZE
				* page_num;

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

struct spci_value spci_mem_retrieve_req_internal (
	uint64_t total_length, uint32_t frag_length, uint64_t base_addr,
	uint32_t page_count, struct vm *from_vm, bool world_switched,
	struct mpool *page_pool)
{
	uint64_t handle;
	uint32_t endpoint_count;
	uint32_t flags;
	uint32_t total_page_count;
	uint32_t constituent_count;
	bool zero_memory;
	struct spci_memory_region_constituent *constituents;
	struct spci_memory_region *src_mem_descriptor;
	struct spci_memory_region *dst_mem_region;
	struct spci_memory_region_constituent *constituent_dst;
	struct spci_memory_region *retrieve_mem_descriptor;

	/* Obtain the handle from the Rx buffer of the caller VM. */

	/* If NULL use TX buffer. */
	if (base_addr){
		panic("TODO: Add support for using separate buffer\n");
	}

	src_mem_descriptor = (struct spci_memory_region *)from_vm->mailbox.send;
	handle = src_mem_descriptor->handle;

	/* Flag checking. */
	flags = src_mem_descriptor->flags;
	// TODO: Add support for zeroing memory
	zero_memory = flags & 0x1; //Bit[0]
	/* Check time slicing (Bit[1]) */
	if (flags & 0x2) {
		/* Not currently supported */
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	dst_mem_region = fetch_region(handle);
	if (!dst_mem_region) {
		dlog("Failed to fetch Handle: %d\n", handle);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/* Check if request if fragmented */
	/* TODO: Add support for fragments. */
	if (total_length != frag_length){
		dlog("Fragment support is not added yet\n");
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/* Check tag matches */
	if (src_mem_descriptor->tag != dst_mem_region->tag){
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/* Check memory permissions do not specify instruction access */
	for (uint32_t index = 0; index < dst_mem_region->endpoint_count; index++)
	{
		uint8_t* src_memory_permissions =
			&dst_mem_region->endpoint_access[index].memory_permission;

		if (((*src_memory_permissions >> 2) & 3)  != 0x0) {
			return spci_error(SPCI_INVALID_PARAMETERS);
		}
	}

	/* Descriptor to populate. */
	retrieve_mem_descriptor = (struct spci_memory_region *)from_vm->mailbox.recv;

	/* Populate fields in receiver RX. Table 44. */
	retrieve_mem_descriptor->handle = src_mem_descriptor->handle;
	retrieve_mem_descriptor->flags = src_mem_descriptor->flags;
	retrieve_mem_descriptor->tag = src_mem_descriptor->tag;
	/* Copy endpoint accesses */
	endpoint_count = dst_mem_region->endpoint_count;
	retrieve_mem_descriptor->endpoint_count = endpoint_count;


	/* Populate Table 40 / 41 */
	for (uint32_t index = 0; index < endpoint_count; index++) {
		/* Table 40. */
		retrieve_mem_descriptor->endpoint_access[index].receiver = dst_mem_region->endpoint_access[index].receiver;
		retrieve_mem_descriptor->endpoint_access[index].memory_permission = dst_mem_region->endpoint_access[index].memory_permission;
		retrieve_mem_descriptor->endpoint_access[index].flags = dst_mem_region->endpoint_access[index].flags;
		/* Table 41.*/
		retrieve_mem_descriptor->endpoint_access[index].composite_off = dst_mem_region->endpoint_access[index].composite_off;
	}

	/* Copy the end points descriptors to the receiver */
	constituents = spci_memory_region_get_constituents(dst_mem_region);
	constituent_count = spci_memory_region_get_composite(dst_mem_region)->constituent_count;
	total_page_count = spci_memory_region_get_composite(dst_mem_region)->total_page_count;

	/* Populate fields in Table 38 for receiver.*/
	spci_memory_region_get_composite(retrieve_mem_descriptor)->constituent_count = constituent_count;
	spci_memory_region_get_composite(retrieve_mem_descriptor)->total_page_count = total_page_count;

	constituent_dst = spci_memory_region_get_constituents(retrieve_mem_descriptor);

	/* Populate table 39's */
	for (uint32_t index = 0; index < constituent_count; index++)
	{
		constituent_dst[index].address = constituents[index].address;
		constituent_dst[index].page_count = constituents[index].page_count;
	}

	/* Set the memory access permissions to XN */
	for (uint32_t index = 0; index < dst_mem_region->endpoint_count; index++)
	{
		uint8_t* ret_memory_permissions =
			&retrieve_mem_descriptor->endpoint_access[index].memory_permission;
		/* Set permission to XN. */
		*ret_memory_permissions |= (0x1 << 2);
	}

	/* TODO: Acquire vm lock. */
	/* Implement the the S-2 mappings. */
	if(!spci_map_region_s2(retrieve_mem_descriptor, from_vm, page_pool))
	{
		return spci_error(SPCI_NO_MEMORY);
	}
	/* TODO: Release vm lock. */


	return (struct spci_value){SPCI_MEM_RETRIEVE_RESP_32, total_length, frag_length, 0, 0, 0, 0, 0};
}

struct spci_value spci_mem_op_resume_internal (uint32_t cookie, struct vm* from_vm)
{
	CHECK(cookie);
	CHECK(retrieve_state[cookie].memory_region);

	uint32_t *filled_constituent = &retrieve_state[cookie].filled_constituent;
	uint32_t total_constituent = spci_memory_region_get_composite(retrieve_state[cookie].memory_region)->constituent_count;

	struct spci_memory_region_constituent *constituent_dst =
		(struct spci_memory_region_constituent *)from_vm->mailbox.recv;

	struct spci_memory_region_constituent *constituent_src =
		&spci_memory_region_get_constituents(retrieve_state[cookie].memory_region)[*filled_constituent];

	uint32_t constituent_count =
		total_constituent - *filled_constituent;

	uint32_t max_frag_c_count = SPCI_PAGE_SIZE/sizeof(struct spci_memory_region_constituent);
	uint32_t frag_size;

	constituent_count = constituent_count < max_frag_c_count ? constituent_count: max_frag_c_count;
	frag_size = constituent_count * sizeof(struct spci_memory_region_constituent);

	for (uint32_t index = 0; index < constituent_count; index++)
	{
		constituent_dst[index].address = constituent_src[index].address;
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

	return (struct spci_value)
		{SPCI_MEM_RETRIEVE_RESP_32, 0, 0, frag_size, 0, cookie, 0, 0};
}


struct spci_value spci_memory_relinquish(struct mem_relinquish_descriptor *relinquish_desc,
	struct mpool *page_pool, struct vm *from_vm)
{
	uint32_t handle;
	uint32_t flags;
	bool zero_memory;
	struct mpool local_page_pool;
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count;
	struct spci_memory_region *memory_region;

	struct vm_locked vm_locked = vm_lock(from_vm);

	mpool_init_with_fallback(&local_page_pool, page_pool);

	/* Obtain the handle from the Rx buffer of the caller VM. */
	handle = relinquish_desc->handle;

	/* Flag checking. */
	flags = relinquish_desc->flags;
	// TODO: Add support for zeroing memory
	zero_memory = flags & 0x1; //Bit[0]
	/* Check time slicing (Bit[1]) */
	if (flags & 0x2) {
		/* Not currently supported */
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	memory_region = fetch_region(handle);
	constituents = spci_memory_region_get_constituents(memory_region);
	constituent_count = spci_memory_region_get_composite(memory_region)->constituent_count;

	for (uint32_t index = 0; index < constituent_count; index++)
	{
		uint32_t page_count = constituents[index].page_count;

		for (uint32_t page_num = 0; page_num < page_count; page_num++)
		{
#if SECURE_WORLD == 1
			uintptr_t address = get_constituent_addr(&constituents[index])
				+ SPCI_PAGE_SIZE * page_num;

			/* Map page on the pages on the retrieve caller. */
			mm_vm_unmap(&vm_locked.vm->ptable, pa_init(address),
				pa_init(address + SPCI_PAGE_SIZE), &local_page_pool);
#endif
		}
	}


	mpool_fini(&local_page_pool);
	vm_unlock(&vm_locked);
	return (struct spci_value){.func = SPCI_SUCCESS_32};
}

struct spci_value spci_memory_reclaim(handle_t handle, uint32_t flags,
	struct vm* current_vm, struct mpool *page_pool)
{
	struct mpool local_page_pool;

	mpool_init_with_fallback(&local_page_pool, page_pool);

	/*
	 * unmap the memory region defined by the handle from the caller VM S2
	 * mapping.
	 */
	erase_region(handle, &local_page_pool);

	//XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
	//
	// Missing S2 unmmapping code.
	//
	//XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX

	/* Make sure we release the freed memory back to the main memory pool. */
	mpool_fini(&local_page_pool);

	return (struct spci_value){.func = SPCI_SUCCESS_32};
}
