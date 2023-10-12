/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa_v1_0.h"

#include <stddef.h>

#include "hf/ffa.h"
#include "hf/types.h"

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/string.h>

#else
#include "hf/static_assert.h"
#include "hf/std.h"
#endif

/**
 * Initializes receiver permissions, in a v1.0 memory transaction descriptor
 * and zero out the other fields to be set later if requred.
 */
void ffa_memory_access_init_v1_0(struct ffa_memory_access_v1_0 *receiver,
				 ffa_id_t receiver_id,
				 enum ffa_data_access data_access,
				 enum ffa_instruction_access instruction_access,
				 ffa_memory_receiver_flags_t flags)
{
	ffa_memory_access_permissions_t permissions = {
		.data_access = data_access,
		.instruction_access = instruction_access,
	};

	*receiver = (struct ffa_memory_access_v1_0){
		.receiver_permissions =
			{
				.receiver = receiver_id,
				.permissions = permissions,
				.flags = flags,
			},
		.composite_memory_region_offset = 0ULL,
		.reserved_0 = 0ULL,
	};
}

/**
 * Initialises the header of the given `ffa_memory_region_v1_0`, not
 * including the composite memory region offset.
 */
void ffa_memory_region_init_header_v1_0(
	struct ffa_memory_region_v1_0 *memory_region, ffa_id_t sender,
	ffa_memory_attributes_t attributes, ffa_memory_region_flags_t flags,
	ffa_memory_handle_t handle, uint32_t tag, uint32_t receiver_count)
{
	memory_region->sender = sender;
	memory_region->attributes = ffa_memory_attributes_truncate(attributes);
	memory_region->reserved_0 = 0;
	memory_region->flags = flags;
	memory_region->handle = handle;
	memory_region->tag = tag;
	memory_region->reserved_1 = 0;
	memory_region->receiver_count = receiver_count;
}

/**
 * Copies as many as possible of the given constituents to the respective
 * memory region and sets the respective offset.
 *
 * Returns the number of constituents remaining which wouldn't fit, and (via
 * return parameters) the size in bytes of the first fragment of data copied to
 * `memory_region` (attributes, constituents and memory region header size), and
 * the total size of the memory sharing message including all constituents.
 */
static uint32_t ffa_memory_region_init_constituents_v1_0(
	struct ffa_memory_region_v1_0 *memory_region,
	size_t memory_region_max_size,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t *total_length,
	uint32_t *fragment_length)
{
	struct ffa_composite_memory_region *composite_memory_region;
	uint32_t fragment_max_constituents;
	uint32_t constituents_offset;
	uint32_t count_to_copy;
	uint32_t i;

	/*
	 * Note that `sizeof(struct_ffa_memory_region)` and `sizeof(struct
	 * ffa_memory_access)` must both be multiples of 16 (as verified by the
	 * asserts in `ffa_memory.c`, so it is guaranteed that the offset we
	 * calculate here is aligned to a 64-bit boundary and so 64-bit values
	 * can be copied without alignment faults.
	 * If there are multiple receiver endpoints, their respective access
	 * structure should point to the same offset value.
	 */
	for (i = 0U; i < memory_region->receiver_count; i++) {
		memory_region->receivers[i].composite_memory_region_offset =
			sizeof(struct ffa_memory_region) +
			memory_region->receiver_count *
				sizeof(struct ffa_memory_access_v1_0);
	}

	composite_memory_region =
		ffa_memory_region_get_composite_v1_0(memory_region, 0);
	composite_memory_region->page_count = 0;
	composite_memory_region->constituent_count = constituent_count;
	composite_memory_region->reserved_0 = 0;

	constituents_offset =
		memory_region->receivers[0].composite_memory_region_offset +
		sizeof(struct ffa_composite_memory_region);
	fragment_max_constituents =
		(memory_region_max_size - constituents_offset) /
		sizeof(struct ffa_memory_region_constituent);

	count_to_copy = constituent_count;
	if (count_to_copy > fragment_max_constituents) {
		count_to_copy = fragment_max_constituents;
	}

	for (i = 0U; i < constituent_count; i++) {
		if (i < count_to_copy) {
			ffa_copy_memory_region_constituents(
				&composite_memory_region->constituents[i],
				&constituents[i]);
		}
		composite_memory_region->page_count +=
			constituents[i].page_count;
	}

	if (total_length != NULL) {
		*total_length =
			constituents_offset +
			composite_memory_region->constituent_count *
				sizeof(struct ffa_memory_region_constituent);
	}
	if (fragment_length != NULL) {
		*fragment_length =
			constituents_offset +
			count_to_copy *
				sizeof(struct ffa_memory_region_constituent);
	}

	return composite_memory_region->constituent_count - count_to_copy;
}

uint32_t ffa_memory_region_init_v1_0(
	struct ffa_memory_region_v1_0 *memory_region,
	size_t memory_region_max_size, ffa_id_t sender,
	struct ffa_memory_access_v1_0 receivers[], uint32_t receiver_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *total_length,
	uint32_t *fragment_length)
{
	ffa_memory_attributes_t attributes = {
		.type = type,
		.cacheability = cacheability,
		.shareability = shareability,
	};

	ffa_memory_region_init_header_v1_0(memory_region, sender, attributes,
					   flags, 0, tag, receiver_count);

#if defined(__linux__) && defined(__KERNEL__)
	memcpy(memory_region->receivers, receivers,
	       receiver_count * sizeof(struct ffa_memory_access_v1_0));
#else
	memcpy_s(memory_region->receivers,
		 MAX_MEM_SHARE_RECIPIENTS *
			 sizeof(struct ffa_memory_access_v1_0),
		 receivers,
		 receiver_count * sizeof(struct ffa_memory_access_v1_0));
#endif

	return ffa_memory_region_init_constituents_v1_0(
		memory_region, memory_region_max_size, constituents,
		constituent_count, total_length, fragment_length);
}

uint32_t ffa_memory_retrieve_request_init_v1_0(
	struct ffa_memory_region_v1_0 *memory_region,
	ffa_memory_handle_t handle, ffa_id_t sender,
	struct ffa_memory_access_v1_0 receivers[], uint32_t receiver_count,
	uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability)
{
	uint32_t i;
	ffa_memory_attributes_t attributes = {
		.type = type,
		.cacheability = cacheability,
		.shareability = shareability,
	};

	ffa_memory_region_init_header_v1_0(memory_region, sender, attributes,
					   flags, handle, tag, receiver_count);

#if defined(__linux__) && defined(__KERNEL__)
	memcpy(memory_region->receivers, receivers,
	       receiver_count * sizeof(struct ffa_memory_access_v1_0));
#else
	memcpy_s(memory_region->receivers,
		 MAX_MEM_SHARE_RECIPIENTS *
			 sizeof(struct ffa_memory_access_v1_0),
		 receivers,
		 receiver_count * sizeof(struct ffa_memory_access_v1_0));
#endif

	/* Zero the composite offset for all receivers */
	for (i = 0U; i < receiver_count; i++) {
		memory_region->receivers[i].composite_memory_region_offset = 0U;
	}

	return sizeof(struct ffa_memory_region_v1_0) +
	       memory_region->receiver_count *
		       sizeof(struct ffa_memory_access_v1_0);
}

ffa_memory_attributes_v1_0 ffa_memory_attributes_truncate(
	ffa_memory_attributes_t attrs)
{
	return (ffa_memory_attributes_v1_0){
		.shareability = attrs.shareability,
		.cacheability = attrs.cacheability,
		.type = attrs.type,
		.security = attrs.security,
	};
}

ffa_memory_attributes_t ffa_memory_attributes_extend(
	ffa_memory_attributes_v1_0 attrs)
{
	return (ffa_memory_attributes_t){
		.shareability = attrs.shareability,
		.cacheability = attrs.cacheability,
		.type = attrs.type,
		.security = attrs.security,
	};
}
