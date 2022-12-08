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

#define SERVICE_PARTITION_INFO_GET(service_name, uuid)                        \
	struct ffa_partition_info* service_name(void* recv)                   \
	{                                                                     \
		static struct ffa_partition_info partition;                   \
		static bool is_set = false;                                   \
		if (!is_set) {                                                \
			ASSERT_EQ(get_ffa_partition_info(uuid, &partition, 1, \
							 recv),               \
				  1);                                         \
			is_set = true;                                        \
		}                                                             \
		return &partition;                                            \
	}

/*
 * The bit 15 of the FF-A ID indicates whether the partition is executing
 * in the normal world, in case it is a Virtual Machine (VM); or in the
 * secure world, in case it is a Secure Partition (SP).
 *
 * If bit 15 is set partition is an SP; if bit 15 is clear partition is
 * a VM.
 */
#define SP_ID_MASK 0x1U << 15
#define SP_ID(x) ((x) | SP_ID_MASK)
#define VM_ID(x) (x & ~SP_ID_MASK)
#define IS_SP_ID(x) ((x & SP_ID_MASK) != 0U)
#define IS_VM_ID(x) ((x & SP_ID_MASK) == 0U)

struct mailbox_buffers {
	void *send;
	void *recv;
};

struct mailbox_buffers set_up_mailbox(void);
ffa_memory_handle_t send_memory_and_retrieve_request_multi_receiver(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, struct ffa_memory_access receivers_send[],
	uint32_t receivers_send_count,
	struct ffa_memory_access receivers_retrieve[],
	uint32_t receivers_retrieve_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags);
ffa_memory_handle_t send_memory_and_retrieve_request(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	ffa_vm_id_t recipient,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags,
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
void send_retrieve_request_single_receiver(
	void *send, ffa_memory_handle_t handle, ffa_vm_id_t sender,
	ffa_vm_id_t receiver, uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability);
void send_retrieve_request(
	void *send, ffa_memory_handle_t handle, ffa_vm_id_t sender,
	struct ffa_memory_access receivers[], uint32_t receiver_count,
	uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, ffa_vm_id_t recipient);
ffa_vm_id_t retrieve_memory_from_message(
	void *recv_buf, void *send_buf, ffa_memory_handle_t *handle,
	struct ffa_memory_region *memory_region_ret,
	size_t memory_region_max_size);
ffa_vm_id_t retrieve_memory_from_message_expect_fail(void *recv_buf,
						     void *send_buf,
						     int32_t expected_error);

ffa_vm_count_t get_ffa_partition_info(struct ffa_uuid *uuid,
				      struct ffa_partition_info *info,
				      size_t info_size, void *recv);

struct ffa_boot_info_header *get_boot_info_header(void);
void dump_boot_info(struct ffa_boot_info_header *boot_info_header);
struct ffa_boot_info_desc *get_boot_info_desc(
	struct ffa_boot_info_header *boot_info_heade, uint8_t type,
	uint8_t type_id);

struct ffa_value send_indirect_message(ffa_vm_id_t from, ffa_vm_id_t to,
				       void *send, const void *payload,
				       size_t payload_size,
				       uint32_t send_flags);
