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

#pragma once

#include <stdint.h>

#include "vmapi/hf/spci.h"

#define SPCI_VERSION_MAJOR 0x1
#define SPCI_VERSION_MINOR 0x0

#define SPCI_VERSION_MAJOR_OFFSET 16

typedef uint64_t handle_t;

struct hv_buffers_t {
	uint8_t *rx;
	uint8_t *tx;
};

static inline struct spci_value spci_error(uint64_t error_code)
{
	return (struct spci_value){.func = SPCI_ERROR_32, .arg2 = error_code};
}

struct vm;
struct mpool;
//struct spci_value spci_memory_relinquish(struct mem_relinquish_descriptor *relinquish_desc, struct mpool *page_pool, struct vm *from_vm);

struct spci_value spci_memory_reclaim(handle_t handle, uint32_t flags, struct vm* current_vm, struct mpool *mpool);

struct spci_value spci_mem_op_resume_internal (uint32_t cookie, struct vm* from_vm);

struct spci_value spci_mem_frag_tx(uint32_t handle_high,
	uint32_t handle_low, uint32_t frag_len, uint32_t agg_sender_id,
	struct vm *from_vm);

struct spci_value spci_mem_frag_rx(uint32_t handle_low,
	uint32_t handle_high, uint32_t frag_offset, uint32_t agg_sender_id, struct vm *from_vm);
