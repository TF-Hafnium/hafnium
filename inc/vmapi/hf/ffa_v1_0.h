/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/types.h"

/**
 * Bits[31:3] of partition properties must be zero for FF-A v1.0.
 * This corresponds to table 8.25 "Partition information descriptor"
 * in DEN0077A FF-A 1.0 REL specification.
 */
#define FFA_PARTITION_v1_0_RES_MASK (~(UINT32_C(0x7)))

/**
 * Create a struct for the "Partition information descriptor" defined for v1.0
 * which can be returned to v1.0 endpoints.
 * This corresponds to table 8.25 "Partition information descriptor"
 * in DEN0077A FF-A 1.0 REL specification.
 */
struct ffa_partition_info_v1_0 {
	ffa_id_t vm_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_partition_properties_t properties;
};

/**
 * Information about a set of pages which are being shared. This corresponds to
 * table 45 of the FF-A 1.0 EAC specification, "Lend, donate or share memory
 * transaction descriptor". Note that it is also used for retrieve requests and
 * responses.
 */
struct ffa_memory_region_v1_0 {
	/**
	 * The ID of the VM which originally sent the memory region, i.e. the
	 * owner.
	 */
	ffa_id_t sender;
	uint8_t attributes;
	/** Reserved field, must be 0. */
	uint8_t reserved_0;
	/** Flags to control behaviour of the transaction. */
	ffa_memory_region_flags_t flags;
	ffa_memory_handle_t handle;
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint64_t tag;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/**
	 * The number of `ffa_memory_access` entries included in this
	 * transaction.
	 */
	uint32_t receiver_count;
	/**
	 * An array of `receiver_count` endpoint memory access descriptors.
	 * Each one specifies a memory region offset, an endpoint and the
	 * attributes with which this memory region should be mapped in that
	 * endpoint's page table.
	 */
	struct ffa_memory_access receivers[];
};

/**
 * Gets the `ffa_composite_memory_region` for the given receiver from an
 * `ffa_memory_region`, or NULL if it is not valid.
 */
static inline struct ffa_composite_memory_region *
ffa_memory_region_get_composite_v1_0(
	struct ffa_memory_region_v1_0 *memory_region, uint32_t receiver_index)
{
	uint32_t offset = memory_region->receivers[receiver_index]
				  .composite_memory_region_offset;

	if (offset == 0) {
		return NULL;
	}

	return (struct ffa_composite_memory_region *)((uint8_t *)memory_region +
						      offset);
}

void ffa_memory_region_init_header_v1_0(
	struct ffa_memory_region_v1_0 *memory_region, ffa_id_t sender,
	ffa_memory_attributes_t attributes, ffa_memory_region_flags_t flags,
	ffa_memory_handle_t handle, uint32_t tag, uint32_t receiver_count);

uint32_t ffa_memory_region_init_v1_0(
	struct ffa_memory_region_v1_0 *memory_region,
	size_t memory_region_max_size, ffa_id_t sender,
	struct ffa_memory_access receivers[], uint32_t receiver_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *total_length,
	uint32_t *fragment_length);

uint32_t ffa_memory_retrieve_request_init_v1_0(
	struct ffa_memory_region_v1_0 *memory_region,
	ffa_memory_handle_t handle, ffa_id_t sender,
	struct ffa_memory_access receivers[], uint32_t receiver_count,
	uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability);
