/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/**
 * The maximum number of memory sharing handles which may be active at once. A
 * DONATE handle is active from when it is sent to when it is retrieved; a SHARE
 * or LEND handle is active from when it is sent to when it is reclaimed.
 */
#pragma once

#define MAX_MEM_SHARES 100

#include <stdbool.h>
#include <stdint.h>

#include "hf/check.h"
#include "hf/ffa_memory.h"
#include "hf/ffa_v1_0.h"
#include "hf/mpool.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

/**
 * The maximum number of fragments into which a memory sharing message may be
 * broken.
 */
#define MAX_FRAGMENTS 20

static_assert(sizeof(struct ffa_memory_region_constituent) % 16 == 0,
	      "struct ffa_memory_region_constituent must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct ffa_composite_memory_region) % 16 == 0,
	      "struct ffa_composite_memory_region must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct ffa_memory_region_attributes) == 4,
	      "struct ffa_memory_region_attributes must be 4 bytes long.");
static_assert(sizeof(struct ffa_memory_access) % 16 == 0,
	      "struct ffa_memory_access must be a multiple of 16 bytes long.");
static_assert(sizeof(struct ffa_memory_region) % 16 == 0,
	      "struct ffa_memory_region must be a multiple of 16 bytes long.");
static_assert(sizeof(struct ffa_mem_relinquish) % 16 == 0,
	      "struct ffa_mem_relinquish must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof((struct ffa_memory_region){0}.receiver_count) == 4,
	      "struct ffa_memory_region::receiver_count must be 4 bytes long");

static_assert(sizeof(struct ffa_features_rxtx_map_params) == 4,
	      "struct ffa_features_rxtx_map_params must be 4 "
	      "bytes long");

static_assert(sizeof(ffa_memory_access_permissions_t) == 1,
	      "ffa_memory_access_permissions_t must be 1 byte wide");
static_assert(sizeof(ffa_memory_attributes_t) == 2,
	      "ffa_memory_attributes_t must be 2 bytes wide");
static_assert(sizeof(ffa_memory_attributes_v1_0) == 1,
	      "ffa_memory_attributes_v1_0 must be 1 byte wide");

struct ffa_memory_share_state {
	/**
	 * The memory region being shared, or NULL if this share state is
	 * unallocated.
	 */
	struct ffa_memory_region *memory_region;

	struct ffa_memory_region_constituent *fragments[MAX_FRAGMENTS];

	/** The number of constituents in each fragment. */
	uint32_t fragment_constituent_counts[MAX_FRAGMENTS];

	/**
	 * The number of valid elements in the `fragments` and
	 * `fragment_constituent_counts` arrays.
	 */
	uint32_t fragment_count;

	/**
	 * The FF-A function used for sharing the memory. Must be one of
	 * FFA_MEM_DONATE_32, FFA_MEM_LEND_32 or FFA_MEM_SHARE_32 if the
	 * share state is allocated, or 0.
	 */
	uint32_t share_func;

	/**
	 * The sender's original mode before invoking the FF-A function for
	 * sharing the memory.
	 * This is used to reset the original configuration when sender invokes
	 * FFA_MEM_RECLAIM_32.
	 */
	uint32_t sender_orig_mode;

	/**
	 * True if all the fragments of this sharing request have been sent and
	 * Hafnium has updated the sender page table accordingly.
	 */
	bool sending_complete;

	/**
	 * How many fragments of the memory region each recipient has retrieved
	 * so far. The order of this array matches the order of the endpoint
	 * memory access descriptors in the memory region descriptor. Any
	 * entries beyond the receiver_count will always be 0.
	 */
	uint32_t retrieved_fragment_count[MAX_MEM_SHARE_RECIPIENTS];

	/**
	 * Field for the SPMC to keep track of how many fragments of the memory
	 * region the hypervisor has managed to retrieve, using a
	 * `hypervisor retrieve request`, as defined by FF-A v1.1 EAC0
	 * specification.
	 */
	uint32_t hypervisor_fragment_count;

	/*
	 * Record whether memory has been protected through the platform
	 * specific means. Used for linking map action on memory send to memory
	 * action on reclaim. I.e. if as a result of memory lend/donate the
	 * memory has been protected, this will be used to reset memory's state,
	 * by unprotecting on reclaim when the sender reestablishes its
	 * ownership and exclusive access.
	 */
	bool memory_protected;
};

/**
 * Actions that can be taken by function `ffa_region_group_identity_map`.
 */
enum ffa_map_action {
	MAP_ACTION_NONE,
	MAP_ACTION_CHECK,
	MAP_ACTION_CHECK_PROTECT,
	MAP_ACTION_COMMIT,
	MAP_ACTION_COMMIT_UNPROTECT,
	MAP_ACTION_MAX,
};

/**
 * Encapsulates the set of share states while the `share_states_lock` is held.
 */
struct share_states_locked {
	struct ffa_memory_share_state *share_states;
};

struct ffa_memory_share_state *allocate_share_state(
	struct share_states_locked share_states, uint32_t share_func,
	struct ffa_memory_region *memory_region, uint32_t fragment_length,
	ffa_memory_handle_t handle);
struct share_states_locked share_states_lock(void);
void share_states_unlock(struct share_states_locked *share_states);
struct ffa_memory_share_state *get_share_state(
	struct share_states_locked share_states, ffa_memory_handle_t handle);
void share_state_free(struct share_states_locked share_states,
		      struct ffa_memory_share_state *share_state,
		      struct mpool *page_pool);
uint32_t share_state_next_fragment_offset(
	struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state);
/** Checks whether the given share state has been fully sent. */
bool share_state_sending_complete(struct share_states_locked share_states,
				  struct ffa_memory_share_state *share_state);
void dump_share_states(void);

struct ffa_value ffa_memory_send_validate(
	struct vm_locked from_locked, struct ffa_memory_region *memory_region,
	uint32_t memory_share_length, uint32_t fragment_length,
	uint32_t share_func);
struct ffa_value ffa_memory_send_complete(
	struct vm_locked from_locked, struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state, struct mpool *page_pool,
	uint32_t *orig_from_mode_ret);
struct ffa_value ffa_memory_send_continue_validate(
	struct share_states_locked share_states, ffa_memory_handle_t handle,
	struct ffa_memory_share_state **share_state_ret, ffa_id_t from_vm_id,
	struct mpool *page_pool);

struct ffa_value ffa_retrieve_check_update(
	struct vm_locked to_locked,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t sender_orig_mode, uint32_t share_func, bool clear,
	struct mpool *page_pool, uint32_t *response_mode,
	bool memory_protected);
struct ffa_value ffa_region_group_identity_map(
	struct vm_locked vm_locked,
	struct ffa_memory_region_constituent **fragments,
	const uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t mode, struct mpool *ppool, enum ffa_map_action action,
	bool *memory_protected);
bool memory_region_receivers_from_other_world(
	struct ffa_memory_region *memory_region);
