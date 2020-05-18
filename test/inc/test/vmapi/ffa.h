/*
 * Copyright 2018 The Hafnium Authors.
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

#define EXPECT_FFA_ERROR(value, ffa_error)       \
	do {                                     \
		struct ffa_value v = (value);    \
		EXPECT_EQ(v.func, FFA_ERROR_32); \
		EXPECT_EQ(v.arg2, (ffa_error));  \
	} while (0)

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
