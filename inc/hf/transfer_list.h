/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/*
 * Copyright (c) 2023-2024, Linaro Limited and Contributors. All rights
 * reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "hf/arch/types.h"

#include "hf/static_assert.h"

#define TRANSFER_LIST_SIGNATURE 0x4a0fb10bU
#define TRANSFER_LIST_VERSION 0x0001U

/*
 * Init value of maximum alignment required by any TE data in the TL
 * specified as a power of two
 */
#define TRANSFER_LIST_INIT_MAX_ALIGN 3U

/* Alignment required by TE header start address, in bytes */
#define TRANSFER_LIST_GRANULE 8UL

/*
 * Version of the register convention used.
 * Set to 1 for both AArch64 and AArch32 according to fw handoff spec v0.9
 */
#define REGISTER_CONVENTION_VERSION_SHIFT_64 32UL
#define REGISTER_CONVENTION_VERSION_SHIFT_32 24UL
#define REGISTER_CONVENTION_VERSION_MASK 0xffUL
#define REGISTER_CONVENTION_VERSION 1UL

#define TRANSFER_LIST_HANDOFF_X1_VALUE(__version)                \
	((TRANSFER_LIST_SIGNATURE &                              \
	  ((1UL << REGISTER_CONVENTION_VERSION_SHIFT_64) - 1)) | \
	 (((__version) & REGISTER_CONVENTION_VERSION_MASK)       \
	  << REGISTER_CONVENTION_VERSION_SHIFT_64))

#define TRANSFER_LIST_HANDOFF_R1_VALUE(__version)                \
	((TRANSFER_LIST_SIGNATURE &                              \
	  ((1UL << REGISTER_CONVENTION_VERSION_SHIFT_32) - 1)) | \
	 (((__version) & REGISTER_CONVENTION_VERSION_MASK)       \
	  << REGISTER_CONVENTION_VERSION_SHIFT_32))

#define TL_FLAGS_HAS_CHECKSUM (1U << 0)

enum transfer_list_tag_id {
	TL_TAG_EMPTY = 0,
	TL_TAG_FDT = 1,
	TL_TAG_HOB_BLOCK = 2,
	TL_TAG_HOB_LIST = 3,
	TL_TAG_ACPI_TABLE_AGGREGATE = 4,
	TL_TAG_OPTEE_PAGABLE_PART = 0x100,
	TL_TAG_DT_SPMC_MANIFEST = 0x101,
	TL_TAG_EXEC_EP_INFO64 = 0x102,
	TL_TAG_FFA_SP_BINARY = 0x103,
	TL_TAG_SRAM_LAYOUT64 = 0x104,
	TL_TAG_DT_FFA_MANIFEST = 0x106,
};

enum transfer_list_ops {
	TL_OPS_NON, /* invalid for any operation */
	TL_OPS_ALL, /* valid for all operations */
	TL_OPS_RO,  /* valid for read only */
	TL_OPS_CUS, /* abort or switch to special code to interpret */
};

struct transfer_list_header {
	uint32_t signature;
	uint8_t checksum;
	uint8_t version;
	uint8_t hdr_size;

	/* max alignment of TE data */
	uint8_t alignment;

	/* TL header + all TEs */
	uint32_t size;
	uint32_t max_size;
	uint32_t flags;

	/* Spare bytes */
	uint32_t reserved;

	/*
	 * Commented out element used to visualize dynamic part of the
	 * data structure.
	 *
	 * Note that struct transfer_list_entry also is dynamic in size
	 * so the elements can't be indexed directly but instead must be
	 * traversed in order
	 *
	 * struct transfer_list_entry entries[];
	 */
};

struct transfer_list_entry {
	uint32_t tag_id : 24;
	uint8_t hdr_size;
	uint32_t data_size;
	/*
	 * Commented out element used to visualize dynamic part of the
	 * data structure.
	 *
	 * Note that padding is added at the end of @data to make to reach
	 * a 8-byte boundary.
	 *
	 * uint8_t	data[ROUNDUP(data_size, 8)];
	 */
};

static_assert(sizeof(struct transfer_list_entry) == 0x8U,
	      "transfer_list_entry size expected to be 0x8.");

void transfer_list_dump(struct transfer_list_header *tl);

enum transfer_list_ops transfer_list_check_header(
	const struct transfer_list_header *tl);

void transfer_list_update_checksum(struct transfer_list_header *tl);
bool transfer_list_verify_checksum(const struct transfer_list_header *tl);

void *transfer_list_entry_data(struct transfer_list_entry *entry);
bool transfer_list_rem(struct transfer_list_header *tl,
		       struct transfer_list_entry *entry);

struct transfer_list_entry *transfer_list_next(
	struct transfer_list_header *tl, struct transfer_list_entry *last);

struct transfer_list_entry *transfer_list_find(struct transfer_list_header *tl,
					       uint32_t tag_id);
