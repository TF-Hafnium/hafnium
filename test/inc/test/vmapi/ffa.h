/*
 * Copyright 2018 The Hafnium Authors.
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

#pragma once

#include "vmapi/hf/ffa.h"

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
ffa_vm_id_t retrieve_memory_from_message(void *recv_buf, void *send_buf,
					 struct ffa_value msg_ret,
					 ffa_memory_handle_t *handle);
ffa_vm_id_t retrieve_memory_from_message_expect_fail(void *recv_buf,
						     void *send_buf,
						     struct ffa_value msg_ret,
						     int32_t expected_error);
