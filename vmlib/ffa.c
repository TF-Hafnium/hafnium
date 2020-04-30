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

#include "hf/ffa.h"

#include <stddef.h>

#include "hf/types.h"

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/string.h>

#else
#include "hf/std.h"
#endif

/**
 * Initialises the given `ffa_memory_region` and copies the constituent
 * information to it. Returns the length in bytes occupied by the data copied to
 * `memory_region` (attributes, constituents and memory region header size).
 */
static uint32_t ffa_memory_region_init_internal(
	struct ffa_memory_region *memory_region, ffa_vm_id_t sender,
	ffa_memory_attributes_t attributes, ffa_memory_region_flags_t flags,
	ffa_memory_handle_t handle, uint32_t tag, ffa_vm_id_t receiver,
	ffa_memory_access_permissions_t permissions,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count)
{
	struct ffa_composite_memory_region *composite_memory_region;
	uint32_t index;
	uint32_t constituents_length =
		constituent_count *
		sizeof(struct ffa_memory_region_constituent);

	memory_region->sender = sender;
	memory_region->attributes = attributes;
	memory_region->reserved_0 = 0;
	memory_region->flags = flags;
	memory_region->handle = handle;
	memory_region->tag = tag;
	memory_region->reserved_1 = 0;
	memory_region->receiver_count = 1;
	memory_region->receivers[0].receiver_permissions.receiver = receiver;
	memory_region->receivers[0].receiver_permissions.permissions =
		permissions;
	memory_region->receivers[0].receiver_permissions.flags = 0;
	/*
	 * Note that `sizeof(struct_ffa_memory_region)` and `sizeof(struct
	 * ffa_memory_access)` must both be multiples of 16 (as verified by the
	 * asserts in `ffa_memory.c`, so it is guaranteed that the offset we
	 * calculate here is aligned to a 64-bit boundary and so 64-bit values
	 * can be copied without alignment faults.
	 */
	memory_region->receivers[0].composite_memory_region_offset =
		sizeof(struct ffa_memory_region) +
		memory_region->receiver_count *
			sizeof(struct ffa_memory_access);
	memory_region->receivers[0].reserved_0 = 0;

	composite_memory_region =
		ffa_memory_region_get_composite(memory_region, 0);

	composite_memory_region->page_count = 0;
	composite_memory_region->constituent_count = constituent_count;
	composite_memory_region->reserved_0 = 0;

	for (index = 0; index < constituent_count; index++) {
		composite_memory_region->constituents[index] =
			constituents[index];
		composite_memory_region->page_count +=
			constituents[index].page_count;
	}

	/*
	 * TODO: Add assert ensuring that the specified message
	 * length is not greater than FFA_MSG_PAYLOAD_MAX.
	 */

	return memory_region->receivers[0].composite_memory_region_offset +
	       sizeof(struct ffa_composite_memory_region) + constituents_length;
}

/**
 * Initialises the given `ffa_memory_region` and copies the constituent
 * information to it. Returns the length in bytes occupied by the data copied to
 * `memory_region` (attributes, constituents and memory region header size).
 */
uint32_t ffa_memory_region_init(
	struct ffa_memory_region *memory_region, ffa_vm_id_t sender,
	ffa_vm_id_t receiver,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability)
{
	ffa_memory_access_permissions_t permissions = 0;
	ffa_memory_attributes_t attributes = 0;

	/* Set memory region's permissions. */
	ffa_set_data_access_attr(&permissions, data_access);
	ffa_set_instruction_access_attr(&permissions, instruction_access);

	/* Set memory region's page attributes. */
	ffa_set_memory_type_attr(&attributes, type);
	ffa_set_memory_cacheability_attr(&attributes, cacheability);
	ffa_set_memory_shareability_attr(&attributes, shareability);

	return ffa_memory_region_init_internal(
		memory_region, sender, attributes, flags, 0, tag, receiver,
		permissions, constituents, constituent_count);
}

uint32_t ffa_memory_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_vm_id_t sender, ffa_vm_id_t receiver, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability)
{
	ffa_memory_access_permissions_t permissions = 0;
	ffa_memory_attributes_t attributes = 0;

	/* Set memory region's permissions. */
	ffa_set_data_access_attr(&permissions, data_access);
	ffa_set_instruction_access_attr(&permissions, instruction_access);

	/* Set memory region's page attributes. */
	ffa_set_memory_type_attr(&attributes, type);
	ffa_set_memory_cacheability_attr(&attributes, cacheability);
	ffa_set_memory_shareability_attr(&attributes, shareability);

	memory_region->sender = sender;
	memory_region->attributes = attributes;
	memory_region->reserved_0 = 0;
	memory_region->flags = flags;
	memory_region->reserved_1 = 0;
	memory_region->handle = handle;
	memory_region->tag = tag;
	memory_region->receiver_count = 1;
	memory_region->receivers[0].receiver_permissions.receiver = receiver;
	memory_region->receivers[0].receiver_permissions.permissions =
		permissions;
	memory_region->receivers[0].receiver_permissions.flags = 0;
	/*
	 * Offset 0 in this case means that the hypervisor should allocate the
	 * address ranges. This is the only configuration supported by Hafnium,
	 * as it enforces 1:1 mappings in the stage 2 page tables.
	 */
	memory_region->receivers[0].composite_memory_region_offset = 0;
	memory_region->receivers[0].reserved_0 = 0;

	return sizeof(struct ffa_memory_region) +
	       memory_region->receiver_count * sizeof(struct ffa_memory_access);
}

uint32_t ffa_memory_lender_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_vm_id_t sender)
{
	memory_region->sender = sender;
	memory_region->attributes = 0;
	memory_region->reserved_0 = 0;
	memory_region->flags = 0;
	memory_region->reserved_1 = 0;
	memory_region->handle = handle;
	memory_region->tag = 0;
	memory_region->receiver_count = 0;

	return sizeof(struct ffa_memory_region);
}

uint32_t ffa_retrieved_memory_region_init(
	struct ffa_memory_region *response, size_t response_max_size,
	ffa_vm_id_t sender, ffa_memory_attributes_t attributes,
	ffa_memory_region_flags_t flags, ffa_memory_handle_t handle,
	ffa_vm_id_t receiver, ffa_memory_access_permissions_t permissions,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count)
{
	/* TODO: Check against response_max_size first. */
	return ffa_memory_region_init_internal(
		response, sender, attributes, flags, handle, 0, receiver,
		permissions, constituents, constituent_count);
}
