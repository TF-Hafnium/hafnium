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

#include "hf/spci.h"

#include <stddef.h>

#include "hf/types.h"

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/string.h>

/* Linux doesn't have a checked memcpy, so just use the unchecked version. */
void memcpy_s(void *dest, size_t destsz, const void *src, size_t count)
{
	memcpy(dest, src, count);
}

/*
 * Use macro from Linux because we can't include Hafnium internal headers here.
 */
#ifndef align_up
#define align_up(v, a) ALIGN((v), (a))
#endif

#else
#include "hf/std.h"
#endif

/**
 * Initialises the given `spci_memory_region` and copies the constituent
 * information to it. Returns the length in bytes occupied by the data copied to
 * `memory_region` (attributes, constituents and memory region header size).
 */
uint32_t spci_memory_region_init(
	struct spci_memory_region *memory_region, spci_vm_id_t sender,
	spci_vm_id_t receiver,
	const struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	spci_memory_region_flags_t flags, enum spci_memory_access access,
	enum spci_memory_type type, enum spci_memory_cacheability cacheability,
	enum spci_memory_shareability shareability)
{
	uint32_t constituents_length =
		constituent_count *
		sizeof(struct spci_memory_region_constituent);
	uint32_t index;
	struct spci_memory_region_constituent *region_constituents;
	uint16_t attributes = 0;

	/* Set memory region's page attributes. */
	spci_set_memory_access_attr(&attributes, access);
	spci_set_memory_type_attr(&attributes, type);
	spci_set_memory_cacheability_attr(&attributes, cacheability);
	spci_set_memory_shareability_attr(&attributes, shareability);

	memory_region->tag = tag;
	memory_region->flags = flags;
	memory_region->sender = sender;
	memory_region->reserved_0 = 0;
	memory_region->reserved_1 = 0;
	memory_region->page_count = 0;
	memory_region->constituent_count = constituent_count;
	memory_region->attribute_count = 1;
	memory_region->attributes[0].receiver = receiver;
	memory_region->attributes[0].memory_attributes = attributes;
	memory_region->attributes[0].reserved_0 = 0;
	memory_region->attributes[0].reserved_1 = 0;

	/*
	 * Constituent offset must be aligned to a 32-bit boundary so that
	 * 32-bit values can be copied without alignment faults.
	 */
	memory_region->constituent_offset = align_up(
		sizeof(struct spci_memory_region) +
			memory_region->attribute_count *
				sizeof(struct spci_memory_region_attributes),
		4);
	region_constituents =
		spci_memory_region_get_constituents(memory_region);

	for (index = 0; index < constituent_count; index++) {
		region_constituents[index] = constituents[index];
		memory_region->page_count += constituents[index].page_count;
	}

	/*
	 * TODO: Add assert ensuring that the specified message
	 * length is not greater than SPCI_MSG_PAYLOAD_MAX.
	 */

	return memory_region->constituent_offset + constituents_length;
}

uint32_t spci_memory_retrieve_request_init(
	struct spci_memory_retrieve_request *request,
	spci_memory_handle_t handle, spci_vm_id_t sender, spci_vm_id_t receiver,
	uint32_t share_func, uint32_t tag, uint32_t page_count,
	enum spci_memory_access access, enum spci_memory_type type,
	enum spci_memory_cacheability cacheability,
	enum spci_memory_shareability shareability)
{
	struct spci_memory_retrieve_properties *retrieve_properties =
		spci_memory_retrieve_request_first_retrieve_properties(request);
	uint16_t attributes = 0;

	/* Set memory region's page attributes. */
	spci_set_memory_access_attr(&attributes, access);
	spci_set_memory_type_attr(&attributes, type);
	spci_set_memory_cacheability_attr(&attributes, cacheability);
	spci_set_memory_shareability_attr(&attributes, shareability);

	request->reserved_0 = 0;
	request->reserved_1 = 0;
	request->handle = handle;
	request->sender = sender;
	request->share_func = share_func;
	request->tag = tag;
	request->attribute_count = 0;
	request->attribute_offset = 0;
	request->retrieve_properties_count = 1;

	retrieve_properties->attributes.receiver = receiver;
	retrieve_properties->attributes.memory_attributes = attributes;
	retrieve_properties->page_count = page_count;
	retrieve_properties->constituent_count = 0;
	retrieve_properties->reserved = 0;

	return sizeof(struct spci_memory_retrieve_request) +
	       sizeof(struct spci_memory_retrieve_properties);
}

uint32_t spci_retrieved_memory_region_init(
	struct spci_retrieved_memory_region *response, size_t response_max_size,
	spci_vm_id_t receiver,
	const struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t page_count)
{
	struct spci_receiver_address_range *response_range =
		spci_retrieved_memory_region_first_receiver_range(response);

	response->receiver_count = 1;
	response_range->receiver = receiver;
	response_range->page_count = page_count;
	response_range->constituent_count = constituent_count;
	memcpy_s(response_range->constituents,
		 response_max_size -
			 sizeof(struct spci_retrieved_memory_region) -
			 sizeof(struct spci_receiver_address_range),
		 constituents,
		 constituent_count *
			 sizeof(struct spci_memory_region_constituent));

	return sizeof(struct spci_retrieved_memory_region) +
	       sizeof(struct spci_receiver_address_range) +
	       constituent_count *
		       sizeof(struct spci_memory_region_constituent);
}
