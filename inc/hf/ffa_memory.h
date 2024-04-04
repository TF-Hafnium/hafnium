/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mpool.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

bool is_ffa_hypervisor_retrieve_request(struct ffa_memory_region *request);

bool ffa_memory_region_sanity_check(struct ffa_memory_region *memory_region,
				    enum ffa_version ffa_version,
				    uint32_t fragment_length,
				    bool send_transaction);

struct ffa_value ffa_memory_send(struct vm_locked from_locked,
				 struct ffa_memory_region *memory_region,
				 uint32_t memory_share_length,
				 uint32_t fragment_length, uint32_t share_func,
				 struct mpool *page_pool);
struct ffa_value ffa_memory_send_continue(struct vm_locked from_locked,
					  void *fragment,
					  uint32_t fragment_length,
					  ffa_memory_handle_t handle,
					  struct mpool *page_pool);
struct ffa_value ffa_memory_retrieve(struct vm_locked to_locked,
				     struct ffa_memory_region *retrieve_request,
				     uint32_t retrieve_request_length,
				     struct mpool *page_pool);
struct ffa_value ffa_memory_retrieve_continue(struct vm_locked to_locked,
					      ffa_memory_handle_t handle,
					      uint32_t fragment_offset,
					      ffa_id_t sender_vm_id,
					      void *retrieve_continue_page,
					      struct mpool *page_pool);
struct ffa_value ffa_memory_relinquish(
	struct vm_locked from_locked,
	struct ffa_mem_relinquish *relinquish_request, struct mpool *page_pool);
struct ffa_value ffa_memory_reclaim(struct vm_locked to_locked,
				    ffa_memory_handle_t handle,
				    ffa_memory_region_flags_t flags,
				    struct mpool *page_pool);
