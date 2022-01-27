/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/ffa.h"

/*
 * A number of pages that is large enough that it must take two fragments to
 * share.
 */
#define FRAGMENTED_SHARE_PAGE_COUNT \
	(PAGE_SIZE / sizeof(struct ffa_memory_region_constituent))

#define EXPECT_FFA_ERROR(value, ffa_error)                 \
	do {                                               \
		struct ffa_value v = (value);              \
		EXPECT_EQ(v.func, FFA_ERROR_32);           \
		EXPECT_EQ(ffa_error_code(v), (ffa_error)); \
	} while (0)

/*
 * The bit 15 of the FF-A ID indicates whether the partition is executing
 * in the normal world, in case it is a Virtual Machine (VM); or in the
 * secure world, in case it is a Secure Partition (SP).
 *
 * If bit 15 is set partition is an SP; if bit 15 is clear partition is
 * a VM.
 */
#define SP_ID_MASK 1 << 15
#define SP_ID(x) ((x) | SP_ID_MASK)
#define VM_ID(x) (x & ~SP_ID_MASK)
#define IS_SP_ID(x) ((x & SP_ID_MASK) != 0U)

struct mailbox_buffers {
	void *send;
	void *recv;
};

struct mailbox_buffers set_up_mailbox(void);
ffa_memory_handle_t send_memory_and_retrieve_request(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	ffa_vm_id_t recipient,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access);
ffa_memory_handle_t send_memory_and_retrieve_request_force_fragmented(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	ffa_vm_id_t recipient,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access);
ffa_vm_id_t retrieve_memory_from_message(
	void *recv_buf, void *send_buf, struct ffa_value msg_ret,
	ffa_memory_handle_t *handle,
	struct ffa_memory_region *memory_region_ret,
	size_t memory_region_max_size);
ffa_vm_id_t retrieve_memory_from_message_expect_fail(void *recv_buf,
						     void *send_buf,
						     struct ffa_value msg_ret,
						     int32_t expected_error);

ffa_vm_count_t get_ffa_partition_info(struct ffa_uuid *uuid,
				      struct ffa_partition_info *info,
				      size_t info_size);

struct ffa_boot_info_header *get_boot_info_header(void);
void dump_boot_info(struct ffa_boot_info_header *boot_info_header);
struct ffa_boot_info_desc *get_boot_info_desc(
	struct ffa_boot_info_header *boot_info_heade, uint8_t type,
	uint8_t type_id);
