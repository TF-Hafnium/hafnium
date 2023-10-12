/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include <stddef.h>

#include "hf/ffa_v1_0.h"
#include "hf/types.h"

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/string.h>
#else
#include "hf/assert.h"
#include "hf/static_assert.h"
#include "hf/std.h"
#endif

/*
 * hf/assert.h is not availble for linux builds as well as the
 * ENABLE_ASSERTIONS and LOG_LEVEL macros it uses so we define the
 * verbose log level macro here for this case.
 */
#if defined(__linux__) && defined(__KERNEL__)
#define assert(e) \
	((e) ? ((void)0) : panic("ASSERT: %s:%d\n", __FILE__, __LINE__, #e))
#endif

static_assert(sizeof(struct ffa_endpoint_rx_tx_descriptor) % 16 == 0,
	      "struct ffa_endpoint_rx_tx_descriptor must be a multiple of 16 "
	      "bytes long.");

void ffa_copy_memory_region_constituents(
	struct ffa_memory_region_constituent *dest,
	const struct ffa_memory_region_constituent *src)
{
	dest->address = src->address;
	dest->page_count = src->page_count;
	dest->reserved = 0;
}

/**
 * Initializes receiver permissions, in a memory transaction descriptor
 * and zero out the other fields to be set later if required.
 */
void ffa_memory_access_init(struct ffa_memory_access *receiver,
			    ffa_id_t receiver_id,
			    enum ffa_data_access data_access,
			    enum ffa_instruction_access instruction_access,
			    ffa_memory_receiver_flags_t flags,
			    struct ffa_memory_access_impdef *impdef_val)
{
	ffa_memory_access_permissions_t permissions = {
		.data_access = data_access,
		.instruction_access = instruction_access,
	};

	*receiver = (struct ffa_memory_access){
		.receiver_permissions =
			{
				.receiver = receiver_id,
				.permissions = permissions,
				.flags = flags,
			},
		.composite_memory_region_offset = 0ULL,
		.impdef = impdef_val != NULL
				  ? *impdef_val
				  : ffa_memory_access_impdef_init(0, 0),
		receiver->reserved_0 = 0ULL,
	};
}

/**
 * Initialises the header of the given `ffa_memory_region`, not
 * including the composite memory region offset.
 */
void ffa_memory_region_init_header(struct ffa_memory_region *memory_region,
				   ffa_id_t sender,
				   ffa_memory_attributes_t attributes,
				   ffa_memory_region_flags_t flags,
				   ffa_memory_handle_t handle, uint32_t tag,
				   uint32_t receiver_count,
				   uint32_t receiver_desc_size)
{
	memory_region->sender = sender;
	memory_region->attributes = attributes;
	memory_region->flags = flags;
	memory_region->handle = handle;
	memory_region->tag = tag;
	memory_region->memory_access_desc_size = receiver_desc_size;
	memory_region->receiver_count = receiver_count;
	memory_region->receivers_offset = sizeof(struct ffa_memory_region);
#if defined(__linux__) && defined(__KERNEL__)
	memset(memory_region->reserved, 0, sizeof(memory_region->reserved));
#else
	memset_s(memory_region->reserved, sizeof(memory_region->reserved), 0,
		 sizeof(memory_region->reserved));
#endif
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
static uint32_t ffa_memory_region_init_constituents(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t *total_length,
	uint32_t *fragment_length)
{
	uint32_t composite_memory_region_offset;
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
	composite_memory_region_offset =
		memory_region->receivers_offset +
		memory_region->receiver_count *
			memory_region->memory_access_desc_size;
	for (i = 0U; i < memory_region->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			ffa_memory_region_get_receiver(memory_region, i);
		assert(receiver != NULL);
		receiver->composite_memory_region_offset =
			composite_memory_region_offset;
	}

	composite_memory_region =
		ffa_memory_region_get_composite(memory_region, 0);
	composite_memory_region->page_count = 0;
	composite_memory_region->constituent_count = constituent_count;
	composite_memory_region->reserved_0 = 0;

	constituents_offset = composite_memory_region_offset +
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

/**
 * Initialises the given `ffa_memory_region` and copies as many as possible of
 * the given constituents to it.
 *
 * Returns the number of constituents remaining which wouldn't fit, and (via
 * return parameters) the size in bytes of the first fragment of data copied to
 * `memory_region` (attributes, constituents and memory region header size), and
 * the total size of the memory sharing message including all constituents.
 */
uint32_t ffa_memory_region_init_single_receiver(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_id_t sender, ffa_id_t receiver,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability,
	struct ffa_memory_access_impdef *impdef_val, uint32_t *total_length,
	uint32_t *fragment_length)
{
	struct ffa_memory_access receiver_access;

	ffa_memory_access_init(&receiver_access, receiver, data_access,
			       instruction_access, 0, impdef_val);

	return ffa_memory_region_init(
		memory_region, memory_region_max_size, sender, &receiver_access,
		1, sizeof(struct ffa_memory_access), constituents,
		constituent_count, tag, flags, type, cacheability, shareability,
		total_length, fragment_length);
}

uint32_t ffa_memory_region_init(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count, uint32_t receiver_desc_size,
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

	ffa_memory_region_init_header(memory_region, sender, attributes, flags,
				      0, tag, receiver_count,
				      receiver_desc_size);

#if defined(__linux__) && defined(__KERNEL__)
	memcpy(ffa_memory_region_get_receiver(memory_region, 0), receivers,
	       receiver_count * memory_region->memory_access_desc_size);
#else
	memcpy_s(ffa_memory_region_get_receiver(memory_region, 0),
		 MAX_MEM_SHARE_RECIPIENTS *
			 memory_region->memory_access_desc_size,
		 receivers,
		 receiver_count * memory_region->memory_access_desc_size);
#endif

	return ffa_memory_region_init_constituents(
		memory_region, memory_region_max_size, constituents,
		constituent_count, total_length, fragment_length);
}

/**
 * Initialises the given `ffa_memory_region` to be used for an
 * `FFA_MEM_RETRIEVE_REQ` by the receiver of a memory transaction.
 *
 * Returns the size of the message written.
 */
uint32_t ffa_memory_retrieve_request_init_single_receiver(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender, ffa_id_t receiver, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability,
	struct ffa_memory_access_impdef *impdef_val)
{
	struct ffa_memory_access receiver_access;

	ffa_memory_access_init(&receiver_access, receiver, data_access,
			       instruction_access, 0, impdef_val);

	return ffa_memory_retrieve_request_init(
		memory_region, handle, sender, &receiver_access, 1,
		sizeof(struct ffa_memory_access), tag, flags, type,
		cacheability, shareability);
}

uint32_t ffa_memory_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count, uint32_t receiver_desc_size, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability)
{
	uint32_t i;
	ffa_memory_attributes_t attributes = {
		.type = type,
		.cacheability = cacheability,
		.shareability = shareability,
	};

	ffa_memory_region_init_header(memory_region, sender, attributes, flags,
				      handle, tag, receiver_count,
				      receiver_desc_size);

#if defined(__linux__) && defined(__KERNEL__)
	memcpy(ffa_memory_region_get_receiver(memory_region, 0), receivers,
	       receiver_count * memory_region->memory_access_desc_size);
#else
	memcpy_s(ffa_memory_region_get_receiver(memory_region, 0),
		 MAX_MEM_SHARE_RECIPIENTS *
			 memory_region->memory_access_desc_size,
		 receivers,
		 receiver_count * memory_region->memory_access_desc_size);
#endif

	/* Zero the composite offset for all receivers */
	for (i = 0U; i < receiver_count; i++) {
		struct ffa_memory_access *receiver =
			ffa_memory_region_get_receiver(memory_region, i);
		assert(receiver != NULL);
		receiver->composite_memory_region_offset = 0U;
	}

	return memory_region->receivers_offset +
	       memory_region->receiver_count *
		       memory_region->memory_access_desc_size;
}

/**
 * Initialises the given `ffa_memory_region` to be used for an
 * `FFA_MEM_RETRIEVE_REQ` from the hypervisor to the TEE.
 *
 * Returns the size of the message written.
 */
uint32_t ffa_memory_lender_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender)
{
	memory_region->sender = sender;
	memory_region->attributes = (ffa_memory_attributes_t){0};
	memory_region->flags = 0;
	memory_region->handle = handle;
	memory_region->tag = 0;
	memory_region->receiver_count = 0;

#if defined(__linux__) && defined(__KERNEL__)
	memset(memory_region->reserved, 0, sizeof(memory_region->reserved));
#else
	memset_s(memory_region->reserved, sizeof(memory_region->reserved), 0,
		 sizeof(memory_region->reserved));
#endif
	return sizeof(struct ffa_memory_region);
}

uint32_t ffa_memory_fragment_init(
	struct ffa_memory_region_constituent *fragment,
	size_t fragment_max_size,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t *fragment_length)
{
	uint32_t fragment_max_constituents =
		fragment_max_size /
		sizeof(struct ffa_memory_region_constituent);
	uint32_t count_to_copy = constituent_count;
	uint32_t i;

	if (count_to_copy > fragment_max_constituents) {
		count_to_copy = fragment_max_constituents;
	}

	for (i = 0; i < count_to_copy; ++i) {
		ffa_copy_memory_region_constituents(&fragment[i],
						    &constituents[i]);
	}

	if (fragment_length != NULL) {
		*fragment_length = count_to_copy *
				   sizeof(struct ffa_memory_region_constituent);
	}

	return constituent_count - count_to_copy;
}

static void ffa_composite_memory_region_init(
	struct ffa_composite_memory_region *composite, uint64_t address,
	uint32_t page_count)
{
	composite->page_count = page_count;
	composite->constituent_count = 1;
	composite->reserved_0 = 0;

	composite->constituents[0].page_count = page_count;
	composite->constituents[0].address = address;
	composite->constituents[0].reserved = 0;
}

/**
 * Initialises the given `ffa_endpoint_rx_tx_descriptor` to be used for an
 * `FFA_RXTX_MAP` forwarding.
 * Each buffer is described by an `ffa_composite_memory_region` containing
 * one `ffa_memory_region_constituent`.
 */
void ffa_endpoint_rx_tx_descriptor_init(
	struct ffa_endpoint_rx_tx_descriptor *desc, ffa_id_t endpoint_id,
	uint64_t rx_address, uint64_t tx_address)
{
	desc->endpoint_id = endpoint_id;
	desc->reserved = 0;
	desc->pad = 0;

	/*
	 * RX's composite descriptor is allocated after the enpoint descriptor.
	 * `sizeof(struct ffa_endpoint_rx_tx_descriptor)` is guaranteed to be
	 * 16-byte aligned.
	 */
	desc->rx_offset = sizeof(struct ffa_endpoint_rx_tx_descriptor);

	ffa_composite_memory_region_init(
		(struct ffa_composite_memory_region *)((uintptr_t)desc +
						       desc->rx_offset),
		rx_address, HF_MAILBOX_SIZE / FFA_PAGE_SIZE);

	/*
	 * TX's composite descriptor is allocated after the RX descriptor.
	 * `sizeof(struct ffa_composite_memory_region)`  and
	 * `sizeof(struct ffa_memory_region_constituent)` are guaranteed to be
	 * 16-byte aligned in ffa_memory.c.
	 */
	desc->tx_offset = desc->rx_offset +
			  sizeof(struct ffa_composite_memory_region) +
			  sizeof(struct ffa_memory_region_constituent);

	ffa_composite_memory_region_init(
		(struct ffa_composite_memory_region *)((uintptr_t)desc +
						       desc->tx_offset),
		tx_address, HF_MAILBOX_SIZE / FFA_PAGE_SIZE);
}
