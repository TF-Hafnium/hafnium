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

#define SERVICE_PARTITION_INFO_GET(service_name, uuid)                         \
	struct ffa_partition_info *service_name(void *recv)                    \
	{                                                                      \
		static struct ffa_partition_info partition;                    \
		static bool is_set = false;                                    \
		struct ffa_uuid to_get_uuid = uuid;                            \
		if (!is_set) {                                                 \
			ASSERT_EQ(get_ffa_partition_info(to_get_uuid,          \
							 &partition, 1, recv), \
				  1);                                          \
			is_set = true;                                         \
		}                                                              \
		return &partition;                                             \
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
#define VM_ID(x) ((x) & ~SP_ID_MASK)

/*
 * Implementation-defined maximum registers that may be used in a
 * direct message response.
 */
#define MAX_MSG_SIZE (14 * sizeof(uint64_t))

struct mailbox_buffers {
	void *send;
	void *recv;
};

struct mailbox_buffers set_up_mailbox(void);
void mailbox_unmap_buffers(struct mailbox_buffers *mb);
void mailbox_receive_retry(void *buffer, size_t buffer_size, void *recv,
			   struct ffa_partition_rxtx_header *header);
ffa_memory_handle_t send_memory_and_retrieve_request_multi_receiver(
	uint32_t share_func, void *tx_buffer, ffa_id_t sender,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, struct ffa_memory_access receivers_send[],
	uint32_t receivers_send_count,
	struct ffa_memory_access receivers_retrieve[],
	uint32_t receivers_retrieve_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags,
	enum ffa_memory_type send_memory_type,
	enum ffa_memory_type receive_memory_type,
	enum ffa_memory_cacheability send_cacheability,
	enum ffa_memory_cacheability receive_cacheability);
ffa_memory_handle_t send_memory_and_retrieve_request(
	uint32_t share_func, void *tx_buffer, ffa_id_t sender,
	ffa_id_t recipient, struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access,
	enum ffa_memory_type send_memory_type,
	enum ffa_memory_type receive_memory_type,
	enum ffa_memory_cacheability send_cacheability,
	enum ffa_memory_cacheability receive_cacheability);
ffa_memory_handle_t send_memory_and_retrieve_request_force_fragmented(
	uint32_t share_func, void *tx_buffer, ffa_id_t sender,
	ffa_id_t recipient, struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access);
void send_retrieve_request_single_receiver(
	void *send, ffa_memory_handle_t handle, ffa_id_t sender,
	ffa_id_t receiver, uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability,
	struct ffa_memory_access_impdef *impdef_val);
void send_retrieve_request(
	void *send, ffa_memory_handle_t handle, ffa_id_t sender,
	struct ffa_memory_access receivers[], uint32_t receiver_count,
	uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, ffa_id_t recipient);
void send_fragmented_memory_region(
	struct ffa_value *send_ret, void *tx_buffer,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t remaining_constituent_count,
	uint32_t sent_length, uint32_t total_length,
	ffa_memory_handle_t *handle, uint64_t allocator_mask);
void memory_region_desc_from_rx_fragments(uint32_t fragment_length,
					  uint32_t total_length,
					  ffa_memory_handle_t handle,
					  void *memory_region, void *recv_buf,
					  uint32_t memory_region_max_size);
void retrieve_memory(void *recv_buf, ffa_memory_handle_t handle,
		     struct ffa_memory_region *memory_region_ret,
		     size_t memory_region_max_size, uint32_t msg_size);
ffa_id_t retrieve_memory_from_message(
	void *recv_buf, void *send_buf, ffa_memory_handle_t *handle,
	struct ffa_memory_region *memory_region_ret,
	size_t memory_region_max_size);
ffa_id_t retrieve_memory_from_message_expect_fail(
	void *recv_buf, void *send_buf, enum ffa_error expected_error);

ffa_vm_count_t get_ffa_partition_info(struct ffa_uuid uuid,
				      struct ffa_partition_info infos[],
				      size_t info_len, void *recv);

struct ffa_boot_info_header *get_boot_info_header(void);
void dump_boot_info(struct ffa_boot_info_header *boot_info_header);
struct ffa_boot_info_desc *get_boot_info_desc(
	struct ffa_boot_info_header *boot_info_heade, uint8_t type,
	uint8_t type_id);

struct ffa_value send_indirect_message(ffa_id_t from, ffa_id_t to, void *send,
				       const void *payload, size_t payload_size,
				       uint32_t send_flags);

void receive_indirect_message(void *buffer, size_t buffer_size, void *recv,
			      ffa_id_t *sender);

bool ffa_partition_info_regs_get_part_info(
	struct ffa_value args, uint8_t idx,
	struct ffa_partition_info *partition_info);

void update_mm_security_state(struct ffa_composite_memory_region *composite,
			      ffa_memory_attributes_t attributes);

uint64_t get_shared_page_from_message(void *recv_buf, void *send_buf,
				      void *retrieve_buffer);

void share_page_with_endpoints(uint64_t page, ffa_id_t receivers_ids[],
			       size_t receivers_count, void *send_buf);
