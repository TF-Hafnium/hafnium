/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include <stddef.h>

#include "hf/types.h"

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/string.h>

#else
#include "hf/static_assert.h"
#include "hf/std.h"
#endif

static_assert(sizeof(struct ffa_endpoint_rx_tx_descriptor) % 16 == 0,
	      "struct ffa_endpoint_rx_tx_descriptor must be a multiple of 16 "
	      "bytes long.");

static void ffa_copy_memory_region_constituents(
	struct ffa_memory_region_constituent *dest,
	const struct ffa_memory_region_constituent *src)
{
	dest->address = src->address;
	dest->page_count = src->page_count;
	dest->reserved = 0;
}

/**
 * Initializes receiver permissions, in a memory transaction descriptor.
 */
void ffa_memory_access_init_permissions(
	struct ffa_memory_access *receiver, ffa_vm_id_t receiver_id,
	enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	ffa_memory_receiver_flags_t flags)
{
	ffa_memory_access_permissions_t permissions = 0;

	/* Set memory region's permissions. */
	ffa_set_data_access_attr(&permissions, data_access);
	ffa_set_instruction_access_attr(&permissions, instruction_access);

	receiver->receiver_permissions.receiver = receiver_id;
	receiver->receiver_permissions.permissions = permissions;
	receiver->receiver_permissions.flags = flags;

	receiver->reserved_0 = 0ULL;
}

/**
 * Initialises the header of the given `ffa_memory_region`, not
 * including the composite memory region offset.
 */
static void ffa_memory_region_init_header(
	struct ffa_memory_region *memory_region, ffa_vm_id_t sender,
	ffa_memory_attributes_t attributes, ffa_memory_region_flags_t flags,
	ffa_memory_handle_t handle, uint32_t tag, uint32_t receiver_count)
{
	memory_region->sender = sender;
	memory_region->attributes = attributes;
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
static uint32_t ffa_memory_region_init_constituents(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
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
				sizeof(struct ffa_memory_access);
	}

	composite_memory_region =
		ffa_memory_region_get_composite(memory_region, 0);
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
	ffa_vm_id_t sender, ffa_vm_id_t receiver,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *total_length,
	uint32_t *fragment_length)
{
	struct ffa_memory_access receiver_access;

	ffa_memory_access_init_permissions(&receiver_access, receiver,
					   data_access, instruction_access, 0);

	return ffa_memory_region_init(
		memory_region, memory_region_max_size, sender, &receiver_access,
		1, constituents, constituent_count, tag, flags, type,
		cacheability, shareability, total_length, fragment_length);
}

uint32_t ffa_memory_region_init(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_vm_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *total_length,
	uint32_t *fragment_length)
{
	ffa_memory_attributes_t attributes = 0;

	/* Set memory region's page attributes. */
	ffa_set_memory_type_attr(&attributes, type);
	ffa_set_memory_cacheability_attr(&attributes, cacheability);
	ffa_set_memory_shareability_attr(&attributes, shareability);

	ffa_memory_region_init_header(memory_region, sender, attributes, flags,
				      0, tag, receiver_count);

#if defined(__linux__) && defined(__KERNEL__)
	memcpy(memory_region->receivers, receivers,
	       receiver_count * sizeof(struct ffa_memory_access));
#else
	memcpy_s(memory_region->receivers,
		 MAX_MEM_SHARE_RECIPIENTS * sizeof(struct ffa_memory_access),
		 receivers, receiver_count * sizeof(struct ffa_memory_access));
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
uint32_t ffa_memory_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_vm_id_t sender, ffa_vm_id_t receiver, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability)
{
	ffa_memory_attributes_t attributes = 0;

	/* Set memory region's page attributes. */
	ffa_set_memory_type_attr(&attributes, type);
	ffa_set_memory_cacheability_attr(&attributes, cacheability);
	ffa_set_memory_shareability_attr(&attributes, shareability);

	ffa_memory_region_init_header(memory_region, sender, attributes, flags,
				      handle, tag, 1);
	ffa_memory_access_init_permissions(&memory_region->receivers[0],
					   receiver, data_access,
					   instruction_access, 0);

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

/**
 * Initialises the given `ffa_memory_region` to be used for an
 * `FFA_MEM_RETRIEVE_REQ` from the hypervisor to the TEE.
 *
 * Returns the size of the message written.
 */
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

/**
 * Initialises the given `ffa_memory_region` to be used for an
 * `FFA_MEM_RETRIEVE_RESP`, including the given constituents for the first
 * fragment.
 *
 * Returns true on success, or false if the given constituents won't all fit in
 * the first fragment.
 */
bool ffa_retrieved_memory_region_init(
	struct ffa_memory_region *response, size_t response_max_size,
	ffa_vm_id_t sender, ffa_memory_attributes_t attributes,
	ffa_memory_region_flags_t flags, ffa_memory_handle_t handle,
	ffa_vm_id_t receiver, ffa_memory_access_permissions_t permissions,
	uint32_t page_count, uint32_t total_constituent_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t fragment_constituent_count, uint32_t *total_length,
	uint32_t *fragment_length)
{
	struct ffa_composite_memory_region *composite_memory_region;
	uint32_t i;
	uint32_t constituents_offset;

	ffa_memory_region_init_header(response, sender, attributes, flags,
				      handle, 0, 1);
	/*
	 * Initialized here as in memory retrieve responses we currently expect
	 * one borrower to be specified.
	 */
	ffa_memory_access_init_permissions(&response->receivers[0], receiver, 0,
					   0, flags);
	response->receivers[0].receiver_permissions.permissions = permissions;

	/*
	 * Note that `sizeof(struct_ffa_memory_region)` and `sizeof(struct
	 * ffa_memory_access)` must both be multiples of 16 (as verified by the
	 * asserts in `ffa_memory.c`, so it is guaranteed that the offset we
	 * calculate here is aligned to a 64-bit boundary and so 64-bit values
	 * can be copied without alignment faults.
	 */
	response->receivers[0].composite_memory_region_offset =
		sizeof(struct ffa_memory_region) +
		response->receiver_count * sizeof(struct ffa_memory_access);

	composite_memory_region = ffa_memory_region_get_composite(response, 0);
	composite_memory_region->page_count = page_count;
	composite_memory_region->constituent_count = total_constituent_count;
	composite_memory_region->reserved_0 = 0;

	constituents_offset =
		response->receivers[0].composite_memory_region_offset +
		sizeof(struct ffa_composite_memory_region);
	if (constituents_offset +
		    fragment_constituent_count *
			    sizeof(struct ffa_memory_region_constituent) >
	    response_max_size) {
		return false;
	}

	for (i = 0; i < fragment_constituent_count; ++i) {
		composite_memory_region->constituents[i] = constituents[i];
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
			fragment_constituent_count *
				sizeof(struct ffa_memory_region_constituent);
	}

	return true;
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
	struct ffa_endpoint_rx_tx_descriptor *desc, ffa_vm_id_t endpoint_id,
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
