/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/vm.h"

bool plat_ffa_is_memory_send_valid(ffa_id_t receiver, ffa_id_t sender,
				   uint32_t share_func, bool multiple_borrower);

/**
 * Encodes memory handle according to section 5.10.2 of the FF-A v1.0 spec.
 */
ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index);

/**
 * Checks whether given handle was allocated by current world, according to
 * handle encoding rules.
 */
bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle);

/**
 * For non-secure memory, retrieve the NS mode if the partition manager supports
 * it. The SPMC will return MM_MODE_NS, and the hypervisor 0 as it only deals
 * with NS accesses by default.
 */
uint32_t plat_ffa_other_world_mode(void);

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current);
bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current);

/*
 * Handles FF-A memory share calls with recipients from the other world.
 */
struct ffa_value plat_ffa_other_world_mem_send(
	struct vm *from, uint32_t share_func,
	struct ffa_memory_region **memory_region, uint32_t length,
	uint32_t fragment_length, struct mpool *page_pool);

/**
 * Handles the memory reclaim if a memory handle from the other world is
 * provided.
 */
struct ffa_value plat_ffa_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool);

/**
 * Handles the continuation of the memory send operation in case the memory
 * region descriptor contains multiple segments.
 */
struct ffa_value plat_ffa_other_world_mem_send_continue(
	struct vm *from, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct mpool *page_pool);

ffa_memory_attributes_t plat_ffa_memory_security_mode(
	ffa_memory_attributes_t attributes, uint32_t mode);
