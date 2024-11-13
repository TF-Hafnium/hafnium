/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/*
 * Copyright (c) 2023, Linaro Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "hf/transfer_list.h"

#include "hf/assert.h"
#include "hf/dlog.h"
#include "hf/std.h"
#include "hf/string.h"

void transfer_list_dump(struct transfer_list_header *tl)
{
	struct transfer_list_entry *te = NULL;
	int i = 0;

	if (tl == NULL) {
		return;
	}

	dlog_info("Dump transfer list:\n");
	dlog_info("signature  0x%x\n", tl->signature);
	dlog_info("checksum   0x%x\n", tl->checksum);
	dlog_info("version    0x%x\n", tl->version);
	dlog_info("hdr_size   0x%x\n", tl->hdr_size);
	dlog_info("alignment  0x%x\n", tl->alignment);
	dlog_info("size       0x%x\n", tl->size);
	dlog_info("max_size   0x%x\n", tl->max_size);
	dlog_info("flags      0x%x\n", tl->flags);

	while (true) {
		te = transfer_list_next(tl, te);
		if (te == NULL) {
			break;
		}
		dlog_info("Entry %d:\n", i++);
		dlog_info("tag_id     0x%x\n", te->tag_id);
		dlog_info("hdr_size   0x%x\n", te->hdr_size);
		dlog_info("data_size  0x%x\n", te->data_size);
		dlog_info("data_addr  0x%lx\n",
			  (unsigned long)transfer_list_entry_data(te));
	}
}

/**
 * Verifying the header of a transfer list
 * Compliant to 2.4.1 of Firmware handoff specification (v0.9)
 * Return transfer list operation status code
 */
enum transfer_list_ops transfer_list_check_header(
	const struct transfer_list_header *tl)
{
	if (tl == NULL) {
		return TL_OPS_NON;
	}

	if (tl->signature != TRANSFER_LIST_SIGNATURE) {
		dlog_error("Bad transfer list signature %#x\n", tl->signature);
		return TL_OPS_NON;
	}

	if (tl->max_size == 0U) {
		dlog_error("Bad transfer list max size %#x\n", tl->max_size);
		return TL_OPS_NON;
	}

	if (tl->size > tl->max_size) {
		dlog_error("Bad transfer list size %#x\n", tl->size);
		return TL_OPS_NON;
	}

	if (tl->hdr_size != sizeof(struct transfer_list_header)) {
		dlog_error("Bad transfer list header size %#x\n", tl->hdr_size);
		return TL_OPS_NON;
	}

	if (!transfer_list_verify_checksum(tl)) {
		dlog_error("Bad transfer list checksum %#x\n", tl->checksum);
		return TL_OPS_NON;
	}

	if (tl->version == 0) {
		dlog_error("Transfer list version is invalid\n");
		return TL_OPS_NON;
	}

	if (tl->version == TRANSFER_LIST_VERSION) {
		dlog_verbose(
			"Transfer list version is valid for all operations\n");
		return TL_OPS_ALL;
	}

	if (tl->version > TRANSFER_LIST_VERSION) {
		dlog_verbose("Transfer list version is valid for read-only\n");
		return TL_OPS_RO;
	}

	return TL_OPS_CUS;
}

/**
 * Enumerate the next transfer entry
 * Return pointer to the next transfer entry or NULL on error
 */
struct transfer_list_entry *transfer_list_next(struct transfer_list_header *tl,
					       struct transfer_list_entry *last)
{
	struct transfer_list_entry *te = NULL;
	uintptr_t tl_ev = 0;
	uintptr_t va = 0;
	uintptr_t ev = 0;
	size_t sz = 0;
	bool overflow = false;

	if (tl == NULL) {
		return NULL;
	}

	tl_ev = (uintptr_t)tl + tl->size;

	if (last != NULL) {
		va = (uintptr_t)last;

		/*
		 * Check if the total size or if roundup to the next entry
		 * overflow
		 */
		overflow = add_overflow(last->hdr_size, last->data_size, &sz) ||
			   add_with_round_up_overflow(
				   va, sz, TRANSFER_LIST_GRANULE, &va);

		if (overflow) {
			return NULL;
		}
	} else {
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		va = (uintptr_t)tl + tl->hdr_size;
	}

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	te = (struct transfer_list_entry *)va;

	if (va + sizeof(*te) > tl_ev || te->hdr_size < sizeof(*te) ||
	    add_overflow(te->hdr_size, te->data_size, &sz) ||
	    add_overflow(va, sz, &ev) || ev > tl_ev) {
		return NULL;
	}

	return te;
}

/**
 * Calculate the byte sum of a transfer list.
 * Return byte sum of the transfer list.
 */
static uint8_t calc_byte_sum(const struct transfer_list_header *tl)
{
	const uint8_t *b = (uint8_t *)tl;
	uint8_t cs = 0;

	for (size_t i = 0; i < tl->size; i++) {
		cs += b[i];
	}

	return cs;
}

/**
 * Verify the checksum of a transfer list.
 * Return true if verified or false if not.
 */
bool transfer_list_verify_checksum(const struct transfer_list_header *tl)
{
	if (tl == NULL) {
		return false;
	}

	if ((tl->flags & TL_FLAGS_HAS_CHECKSUM) == 0U) {
		return true;
	}

	return calc_byte_sum(tl) == (uint8_t)0;
}

/**
 * Search for an existing transfer entry with the specified tag id from a
 * transfer list
 * Return pointer to the found transfer entry or NULL on error
 */
struct transfer_list_entry *transfer_list_find(struct transfer_list_header *tl,
					       uint32_t tag_id)
{
	struct transfer_list_entry *te = NULL;

	do {
		te = transfer_list_next(tl, te);
	} while (te && (te->tag_id != tag_id));

	return te;
}

/**
 * Retrieve the data pointer of a specified transfer entry
 * Return pointer to the transfer entry data or NULL on error
 */
void *transfer_list_entry_data(struct transfer_list_entry *entry)
{
	if (!entry) {
		return NULL;
	}

	return (uint8_t *)entry + entry->hdr_size;
}
