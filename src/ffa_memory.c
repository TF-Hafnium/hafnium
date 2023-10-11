/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa_memory.h"

#include "hf/arch/mm.h"
#include "hf/arch/other_world.h"
#include "hf/arch/plat/ffa.h"

#include "hf/addr.h"
#include "hf/api.h"
#include "hf/assert.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/ffa_memory_internal.h"
#include "hf/ffa_partition_manifest.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa_v1_0.h"

#define RECEIVERS_COUNT_IN_RETRIEVE_RESP 1

/**
 * All access to members of a `struct ffa_memory_share_state` must be guarded
 * by this lock.
 */
static struct spinlock share_states_lock_instance = SPINLOCK_INIT;
static struct ffa_memory_share_state share_states[MAX_MEM_SHARES];

/**
 * Extracts the index from a memory handle allocated by Hafnium's current world.
 */
uint64_t ffa_memory_handle_get_index(ffa_memory_handle_t handle)
{
	return handle & ~FFA_MEMORY_HANDLE_ALLOCATOR_MASK;
}

/**
 * Initialises the next available `struct ffa_memory_share_state`. If `handle`
 * is `FFA_MEMORY_HANDLE_INVALID` then allocates an appropriate handle,
 * otherwise uses the provided handle which is assumed to be globally unique.
 *
 * Returns a pointer to the allocated `ffa_memory_share_state` on success or
 * `NULL` if none are available.
 */
struct ffa_memory_share_state *allocate_share_state(
	struct share_states_locked share_states, uint32_t share_func,
	struct ffa_memory_region *memory_region, uint32_t fragment_length,
	ffa_memory_handle_t handle)
{
	assert(share_states.share_states != NULL);
	assert(memory_region != NULL);

	for (uint64_t i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states.share_states[i].share_func == 0) {
			struct ffa_memory_share_state *allocated_state =
				&share_states.share_states[i];
			struct ffa_composite_memory_region *composite =
				ffa_memory_region_get_composite(memory_region,
								0);

			if (handle == FFA_MEMORY_HANDLE_INVALID) {
				memory_region->handle =
					plat_ffa_memory_handle_make(i);
			} else {
				memory_region->handle = handle;
			}
			allocated_state->share_func = share_func;
			allocated_state->memory_region = memory_region;
			allocated_state->fragment_count = 1;
			allocated_state->fragments[0] = composite->constituents;
			allocated_state->fragment_constituent_counts[0] =
				(fragment_length -
				 ffa_composite_constituent_offset(memory_region,
								  0)) /
				sizeof(struct ffa_memory_region_constituent);
			allocated_state->sending_complete = false;
			for (uint32_t j = 0; j < MAX_MEM_SHARE_RECIPIENTS;
			     ++j) {
				allocated_state->retrieved_fragment_count[j] =
					0;
			}
			return allocated_state;
		}
	}

	return NULL;
}

/** Locks the share states lock. */
struct share_states_locked share_states_lock(void)
{
	sl_lock(&share_states_lock_instance);

	return (struct share_states_locked){.share_states = share_states};
}

/** Unlocks the share states lock. */
void share_states_unlock(struct share_states_locked *share_states)
{
	assert(share_states->share_states != NULL);
	share_states->share_states = NULL;
	sl_unlock(&share_states_lock_instance);
}

/**
 * If the given handle is a valid handle for an allocated share state then
 * returns a pointer to the share state. Otherwise returns NULL.
 */
struct ffa_memory_share_state *get_share_state(
	struct share_states_locked share_states, ffa_memory_handle_t handle)
{
	struct ffa_memory_share_state *share_state;

	assert(share_states.share_states != NULL);

	/*
	 * First look for a share_state allocated by us, in which case the
	 * handle is based on the index.
	 */
	if (plat_ffa_memory_handle_allocated_by_current_world(handle)) {
		uint64_t index = ffa_memory_handle_get_index(handle);

		if (index < MAX_MEM_SHARES) {
			share_state = &share_states.share_states[index];
			if (share_state->share_func != 0) {
				return share_state;
			}
		}
	}

	/* Fall back to a linear scan. */
	for (uint64_t index = 0; index < MAX_MEM_SHARES; ++index) {
		share_state = &share_states.share_states[index];
		if (share_state->memory_region != NULL &&
		    share_state->memory_region->handle == handle &&
		    share_state->share_func != 0) {
			return share_state;
		}
	}

	return NULL;
}

/** Marks a share state as unallocated. */
void share_state_free(struct share_states_locked share_states,
		      struct ffa_memory_share_state *share_state,
		      struct mpool *page_pool)
{
	uint32_t i;

	assert(share_states.share_states != NULL);
	share_state->share_func = 0;
	share_state->sending_complete = false;
	mpool_free(page_pool, share_state->memory_region);
	/*
	 * First fragment is part of the same page as the `memory_region`, so it
	 * doesn't need to be freed separately.
	 */
	share_state->fragments[0] = NULL;
	share_state->fragment_constituent_counts[0] = 0;
	for (i = 1; i < share_state->fragment_count; ++i) {
		mpool_free(page_pool, share_state->fragments[i]);
		share_state->fragments[i] = NULL;
		share_state->fragment_constituent_counts[i] = 0;
	}
	share_state->fragment_count = 0;
	share_state->memory_region = NULL;
	share_state->hypervisor_fragment_count = 0;
}

/** Checks whether the given share state has been fully sent. */
bool share_state_sending_complete(struct share_states_locked share_states,
				  struct ffa_memory_share_state *share_state)
{
	struct ffa_composite_memory_region *composite;
	uint32_t expected_constituent_count;
	uint32_t fragment_constituent_count_total = 0;
	uint32_t i;

	/* Lock must be held. */
	assert(share_states.share_states != NULL);

	/*
	 * Share state must already be valid, or it's not possible to get hold
	 * of it.
	 */
	CHECK(share_state->memory_region != NULL &&
	      share_state->share_func != 0);

	composite =
		ffa_memory_region_get_composite(share_state->memory_region, 0);
	expected_constituent_count = composite->constituent_count;
	for (i = 0; i < share_state->fragment_count; ++i) {
		fragment_constituent_count_total +=
			share_state->fragment_constituent_counts[i];
	}
	dlog_verbose(
		"Checking completion: constituent count %d/%d from %d "
		"fragments.\n",
		fragment_constituent_count_total, expected_constituent_count,
		share_state->fragment_count);

	return fragment_constituent_count_total == expected_constituent_count;
}

/**
 * Calculates the offset of the next fragment expected for the given share
 * state.
 */
uint32_t share_state_next_fragment_offset(
	struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state)
{
	uint32_t next_fragment_offset;
	uint32_t i;

	/* Lock must be held. */
	assert(share_states.share_states != NULL);

	next_fragment_offset =
		ffa_composite_constituent_offset(share_state->memory_region, 0);
	for (i = 0; i < share_state->fragment_count; ++i) {
		next_fragment_offset +=
			share_state->fragment_constituent_counts[i] *
			sizeof(struct ffa_memory_region_constituent);
	}

	return next_fragment_offset;
}

static void dump_memory_region(struct ffa_memory_region *memory_region)
{
	uint32_t i;

	if (LOG_LEVEL < LOG_LEVEL_VERBOSE) {
		return;
	}

	dlog("from VM %#x, attributes %#x, flags %#x, tag %u, to "
	     "%u "
	     "recipients [",
	     memory_region->sender, memory_region->attributes,
	     memory_region->flags, memory_region->tag,
	     memory_region->receiver_count);
	for (i = 0; i < memory_region->receiver_count; ++i) {
		if (i != 0) {
			dlog(", ");
		}
		dlog("VM %#x: %#x (offset %u)",
		     memory_region->receivers[i].receiver_permissions.receiver,
		     memory_region->receivers[i]
			     .receiver_permissions.permissions,
		     memory_region->receivers[i]
			     .composite_memory_region_offset);
	}
	dlog("]");
}

void dump_share_states(void)
{
	uint32_t i;

	if (LOG_LEVEL < LOG_LEVEL_VERBOSE) {
		return;
	}

	dlog("Current share states:\n");
	sl_lock(&share_states_lock_instance);
	for (i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states[i].share_func != 0) {
			switch (share_states[i].share_func) {
			case FFA_MEM_SHARE_32:
				dlog("SHARE");
				break;
			case FFA_MEM_LEND_32:
				dlog("LEND");
				break;
			case FFA_MEM_DONATE_32:
				dlog("DONATE");
				break;
			default:
				dlog("invalid share_func %#x",
				     share_states[i].share_func);
			}
			dlog(" %#x (", share_states[i].memory_region->handle);
			dump_memory_region(share_states[i].memory_region);
			if (share_states[i].sending_complete) {
				dlog("): fully sent");
			} else {
				dlog("): partially sent");
			}
			dlog(" with %d fragments, %d retrieved, "
			     " sender's original mode: %#x\n",
			     share_states[i].fragment_count,
			     share_states[i].retrieved_fragment_count[0],
			     share_states[i].sender_orig_mode);
		}
	}
	sl_unlock(&share_states_lock_instance);
}

/* TODO: Add device attributes: GRE, cacheability, shareability. */
static inline uint32_t ffa_memory_permissions_to_mode(
	ffa_memory_access_permissions_t permissions, uint32_t default_mode)
{
	uint32_t mode = 0;

	switch (ffa_get_data_access_attr(permissions)) {
	case FFA_DATA_ACCESS_RO:
		mode = MM_MODE_R;
		break;
	case FFA_DATA_ACCESS_RW:
		mode = MM_MODE_R | MM_MODE_W;
		break;
	case FFA_DATA_ACCESS_NOT_SPECIFIED:
		mode = (default_mode & (MM_MODE_R | MM_MODE_W));
		break;
	case FFA_DATA_ACCESS_RESERVED:
		panic("Tried to convert FFA_DATA_ACCESS_RESERVED.");
	}

	switch (ffa_get_instruction_access_attr(permissions)) {
	case FFA_INSTRUCTION_ACCESS_NX:
		break;
	case FFA_INSTRUCTION_ACCESS_X:
		mode |= MM_MODE_X;
		break;
	case FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED:
		mode |= (default_mode & MM_MODE_X);
		break;
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		panic("Tried to convert FFA_INSTRUCTION_ACCESS_RESVERVED.");
	}

	/* Set the security state bit if necessary. */
	if ((default_mode & plat_ffa_other_world_mode()) != 0) {
		mode |= plat_ffa_other_world_mode();
	}

	return mode;
}

/**
 * Get the current mode in the stage-2 page table of the given vm of all the
 * pages in the given constituents, if they all have the same mode, or return
 * an appropriate FF-A error if not.
 */
static struct ffa_value constituents_get_mode(
	struct vm_locked vm, uint32_t *orig_mode,
	struct ffa_memory_region_constituent **fragments,
	const uint32_t *fragment_constituent_counts, uint32_t fragment_count)
{
	uint32_t i;
	uint32_t j;

	if (fragment_count == 0 || fragment_constituent_counts[0] == 0) {
		/*
		 * Fail if there are no constituents. Otherwise we would get an
		 * uninitialised *orig_mode.
		 */
		dlog_verbose("%s: no constituents\n", __func__);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	for (i = 0; i < fragment_count; ++i) {
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			ipaddr_t begin = ipa_init(fragments[i][j].address);
			size_t size = fragments[i][j].page_count * PAGE_SIZE;
			ipaddr_t end = ipa_add(begin, size);
			uint32_t current_mode;

			/* Fail if addresses are not page-aligned. */
			if (!is_aligned(ipa_addr(begin), PAGE_SIZE) ||
			    !is_aligned(ipa_addr(end), PAGE_SIZE)) {
				dlog_verbose("%s: addresses not page-aligned\n",
					     __func__);
				return ffa_error(FFA_INVALID_PARAMETERS);
			}

			/*
			 * Ensure that this constituent memory range is all
			 * mapped with the same mode.
			 */
			if (!vm_mem_get_mode(vm, begin, end, &current_mode)) {
				dlog_verbose(
					"%s: constituent memory range %#x..%#x "
					"not mapped with the same mode\n",
					__func__, begin, end);
				return ffa_error(FFA_DENIED);
			}

			/*
			 * Ensure that all constituents are mapped with the same
			 * mode.
			 */
			if (i == 0) {
				*orig_mode = current_mode;
			} else if (current_mode != *orig_mode) {
				dlog_verbose(
					"%s: expected mode %#x but was %#x for "
					"%d pages at %#x.\n",
					__func__, *orig_mode, current_mode,
					fragments[i][j].page_count,
					ipa_addr(begin));
				return ffa_error(FFA_DENIED);
			}
		}
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Verify that all pages have the same mode, that the starting mode
 * constitutes a valid state and obtain the next mode to apply
 * to the sending VM.
 *
 * Returns:
 *   1) FFA_DENIED if a state transition was not found;
 *   2) FFA_DENIED if the pages being shared do not have the same mode within
 *     the <from> VM;
 *   3) FFA_INVALID_PARAMETERS if the beginning and end IPAs are not page
 *     aligned;
 *   4) FFA_INVALID_PARAMETERS if the requested share type was not handled.
 *  Or FFA_SUCCESS on success.
 */
static struct ffa_value ffa_send_check_transition(
	struct vm_locked from, uint32_t share_func,
	struct ffa_memory_access *receivers, uint32_t receivers_count,
	uint32_t *orig_from_mode,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	struct ffa_value ret;

	ret = constituents_get_mode(from, orig_from_mode, fragments,
				    fragment_constituent_counts,
				    fragment_count);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Inconsistent modes.\n");
		return ret;
	}

	/* Ensure the address range is normal memory and not a device. */
	if ((*orig_from_mode & MM_MODE_D) != 0U) {
		dlog_verbose("Can't share device memory (mode is %#x).\n",
			     *orig_from_mode);
		return ffa_error(FFA_DENIED);
	}

	/*
	 * Ensure the sender is the owner and has exclusive access to the
	 * memory.
	 */
	if ((*orig_from_mode & state_mask) != 0) {
		return ffa_error(FFA_DENIED);
	}

	assert(receivers != NULL && receivers_count > 0U);

	for (uint32_t i = 0U; i < receivers_count; i++) {
		ffa_memory_access_permissions_t permissions =
			receivers[i].receiver_permissions.permissions;
		uint32_t required_from_mode = ffa_memory_permissions_to_mode(
			permissions, *orig_from_mode);

		/*
		 * The assumption is that at this point, the operation from
		 * SP to a receiver VM, should have returned an FFA_ERROR
		 * already.
		 */
		if (!ffa_is_vm_id(from.vm->id)) {
			assert(!ffa_is_vm_id(
				receivers[i].receiver_permissions.receiver));
		}

		if ((*orig_from_mode & required_from_mode) !=
		    required_from_mode) {
			dlog_verbose(
				"Sender tried to send memory with permissions "
				"which required mode %#x but only had %#x "
				"itself.\n",
				required_from_mode, *orig_from_mode);
			return ffa_error(FFA_DENIED);
		}
	}

	/* Find the appropriate new mode. */
	*from_mode = ~state_mask & *orig_from_mode;
	switch (share_func) {
	case FFA_MEM_DONATE_32:
		*from_mode |= MM_MODE_INVALID | MM_MODE_UNOWNED;
		break;

	case FFA_MEM_LEND_32:
		*from_mode |= MM_MODE_INVALID;
		break;

	case FFA_MEM_SHARE_32:
		*from_mode |= MM_MODE_SHARED;
		break;

	default:
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

static struct ffa_value ffa_relinquish_check_transition(
	struct vm_locked from, uint32_t *orig_from_mode,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	uint32_t orig_from_state;
	struct ffa_value ret;

	ret = constituents_get_mode(from, orig_from_mode, fragments,
				    fragment_constituent_counts,
				    fragment_count);
	if (ret.func != FFA_SUCCESS_32) {
		return ret;
	}

	/* Ensure the address range is normal memory and not a device. */
	if (*orig_from_mode & MM_MODE_D) {
		dlog_verbose("Can't relinquish device memory (mode is %#x).\n",
			     *orig_from_mode);
		return ffa_error(FFA_DENIED);
	}

	/*
	 * Ensure the relinquishing VM is not the owner but has access to the
	 * memory.
	 */
	orig_from_state = *orig_from_mode & state_mask;
	if ((orig_from_state & ~MM_MODE_SHARED) != MM_MODE_UNOWNED) {
		dlog_verbose(
			"Tried to relinquish memory in state %#x (masked %#x "
			"but should be %#x).\n",
			*orig_from_mode, orig_from_state, MM_MODE_UNOWNED);
		return ffa_error(FFA_DENIED);
	}

	/* Find the appropriate new mode. */
	*from_mode = (~state_mask & *orig_from_mode) | MM_MODE_UNMAPPED_MASK;

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Verify that all pages have the same mode, that the starting mode
 * constitutes a valid state and obtain the next mode to apply
 * to the retrieving VM.
 *
 * Returns:
 *   1) FFA_DENIED if a state transition was not found;
 *   2) FFA_DENIED if the pages being shared do not have the same mode within
 *     the <to> VM;
 *   3) FFA_INVALID_PARAMETERS if the beginning and end IPAs are not page
 *     aligned;
 *   4) FFA_INVALID_PARAMETERS if the requested share type was not handled.
 *  Or FFA_SUCCESS on success.
 */
struct ffa_value ffa_retrieve_check_transition(
	struct vm_locked to, uint32_t share_func,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t memory_to_attributes, uint32_t *to_mode)
{
	uint32_t orig_to_mode;
	struct ffa_value ret;

	ret = constituents_get_mode(to, &orig_to_mode, fragments,
				    fragment_constituent_counts,
				    fragment_count);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Inconsistent modes.\n");
		return ret;
	}

	if (share_func == FFA_MEM_RECLAIM_32) {
		/*
		 * If the original ffa memory send call has been processed
		 * successfully, it is expected the orig_to_mode would overlay
		 * with `state_mask`, as a result of the function
		 * `ffa_send_check_transition`.
		 */
		if (vm_id_is_current_world(to.vm->id)) {
			assert((orig_to_mode &
				(MM_MODE_INVALID | MM_MODE_UNOWNED |
				 MM_MODE_SHARED)) != 0U);
		}
	} else {
		/*
		 * If the retriever is from virtual FF-A instance:
		 * Ensure the retriever has the expected state. We don't care
		 * about the MM_MODE_SHARED bit; either with or without it set
		 * are both valid representations of the !O-NA state.
		 */
		if (vm_id_is_current_world(to.vm->id) &&
		    to.vm->id != HF_PRIMARY_VM_ID &&
		    (orig_to_mode & MM_MODE_UNMAPPED_MASK) !=
			    MM_MODE_UNMAPPED_MASK) {
			return ffa_error(FFA_DENIED);
		}
	}

	/* Find the appropriate new mode. */
	*to_mode = memory_to_attributes;
	switch (share_func) {
	case FFA_MEM_DONATE_32:
		*to_mode |= 0;
		break;

	case FFA_MEM_LEND_32:
		*to_mode |= MM_MODE_UNOWNED;
		break;

	case FFA_MEM_SHARE_32:
		*to_mode |= MM_MODE_UNOWNED | MM_MODE_SHARED;
		break;

	case FFA_MEM_RECLAIM_32:
		*to_mode |= 0;
		break;

	default:
		dlog_error("Invalid share_func %#x.\n", share_func);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Updates a VM's page table such that the given set of physical address ranges
 * are mapped in the address space at the corresponding address ranges, in the
 * mode provided.
 *
 * If commit is false, the page tables will be allocated from the mpool but no
 * mappings will actually be updated. This function must always be called first
 * with commit false to check that it will succeed before calling with commit
 * true, to avoid leaving the page table in a half-updated state. To make a
 * series of changes atomically you can call them all with commit false before
 * calling them all with commit true.
 *
 * vm_ptable_defrag should always be called after a series of page table
 * updates, whether they succeed or fail.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made to memory mappings.
 */
bool ffa_region_group_identity_map(
	struct vm_locked vm_locked,
	struct ffa_memory_region_constituent **fragments,
	const uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t mode, struct mpool *ppool, bool commit)
{
	uint32_t i;
	uint32_t j;

	if (vm_locked.vm->el0_partition) {
		mode |= MM_MODE_USER | MM_MODE_NG;
	}

	/* Iterate over the memory region constituents within each fragment. */
	for (i = 0; i < fragment_count; ++i) {
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			size_t size = fragments[i][j].page_count * PAGE_SIZE;
			paddr_t pa_begin =
				pa_from_ipa(ipa_init(fragments[i][j].address));
			paddr_t pa_end = pa_add(pa_begin, size);
			uint32_t pa_bits =
				arch_mm_get_pa_bits(arch_mm_get_pa_range());

			/*
			 * Ensure the requested region falls into system's PA
			 * range.
			 */
			if (((pa_addr(pa_begin) >> pa_bits) > 0) ||
			    ((pa_addr(pa_end) >> pa_bits) > 0)) {
				dlog_error("Region is outside of PA Range\n");
				return false;
			}

			if (commit) {
				vm_identity_commit(vm_locked, pa_begin, pa_end,
						   mode, ppool, NULL);
			} else if (!vm_identity_prepare(vm_locked, pa_begin,
							pa_end, mode, ppool)) {
				return false;
			}
		}
	}

	return true;
}

/**
 * Clears a region of physical memory by overwriting it with zeros. The data is
 * flushed from the cache so the memory has been cleared across the system.
 */
static bool clear_memory(paddr_t begin, paddr_t end, struct mpool *ppool,
			 uint32_t extra_mode_attributes)
{
	/*
	 * TODO: change this to a CPU local single page window rather than a
	 *       global mapping of the whole range. Such an approach will limit
	 *       the changes to stage-1 tables and will allow only local
	 *       invalidation.
	 */
	bool ret;
	struct mm_stage1_locked stage1_locked = mm_lock_stage1();
	void *ptr = mm_identity_map(stage1_locked, begin, end,
				    MM_MODE_W | (extra_mode_attributes &
						 plat_ffa_other_world_mode()),
				    ppool);
	size_t size = pa_difference(begin, end);

	if (!ptr) {
		goto fail;
	}

	memset_s(ptr, size, 0, size);
	arch_mm_flush_dcache(ptr, size);
	mm_unmap(stage1_locked, begin, end, ppool);

	ret = true;
	goto out;

fail:
	ret = false;

out:
	mm_unlock_stage1(&stage1_locked);

	return ret;
}

/**
 * Clears a region of physical memory by overwriting it with zeros. The data is
 * flushed from the cache so the memory has been cleared across the system.
 */
static bool ffa_clear_memory_constituents(
	uint32_t security_state_mode,
	struct ffa_memory_region_constituent **fragments,
	const uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	struct mpool *page_pool)
{
	struct mpool local_page_pool;
	uint32_t i;
	bool ret = false;

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure each constituent that is mapped can be
	 * unmapped again afterwards.
	 */
	mpool_init_with_fallback(&local_page_pool, page_pool);

	/* Iterate over the memory region constituents within each fragment. */
	for (i = 0; i < fragment_count; ++i) {
		uint32_t j;

		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			size_t size = fragments[i][j].page_count * PAGE_SIZE;
			paddr_t begin =
				pa_from_ipa(ipa_init(fragments[i][j].address));
			paddr_t end = pa_add(begin, size);

			if (!clear_memory(begin, end, &local_page_pool,
					  security_state_mode)) {
				/*
				 * api_clear_memory will defrag on failure, so
				 * no need to do it here.
				 */
				goto out;
			}
		}
	}

	ret = true;

out:
	mpool_fini(&local_page_pool);
	return ret;
}

static bool is_memory_range_within(ipaddr_t begin, ipaddr_t end,
				   ipaddr_t in_begin, ipaddr_t in_end)
{
	return (ipa_addr(begin) >= ipa_addr(in_begin) &&
		ipa_addr(begin) < ipa_addr(in_end)) ||
	       (ipa_addr(end) <= ipa_addr(in_end) &&
		ipa_addr(end) > ipa_addr(in_begin));
}

/**
 * Receives a memory range and looks for overlaps with the remainder
 * constituents of the memory share/lend/donate operation. Assumes they are
 * passed in order to avoid having to loop over all the elements at each call.
 * The function only compares the received memory ranges with those that follow
 * within the same fragment, and subsequent fragments from the same operation.
 */
static bool ffa_memory_check_overlap(
	struct ffa_memory_region_constituent **fragments,
	const uint32_t *fragment_constituent_counts,
	const uint32_t fragment_count, const uint32_t current_fragment,
	const uint32_t current_constituent)
{
	uint32_t i = current_fragment;
	uint32_t j = current_constituent;
	ipaddr_t current_begin = ipa_init(fragments[i][j].address);
	const uint32_t current_page_count = fragments[i][j].page_count;
	size_t current_size = current_page_count * PAGE_SIZE;
	ipaddr_t current_end = ipa_add(current_begin, current_size - 1);

	if (current_size == 0 ||
	    current_size > UINT64_MAX - ipa_addr(current_begin)) {
		dlog_verbose("Invalid page count. Addr: %x page_count: %x\n",
			     current_begin, current_page_count);
		return false;
	}

	for (; i < fragment_count; i++) {
		j = (i == current_fragment) ? j + 1 : 0;

		for (; j < fragment_constituent_counts[i]; j++) {
			ipaddr_t begin = ipa_init(fragments[i][j].address);
			const uint32_t page_count = fragments[i][j].page_count;
			size_t size = page_count * PAGE_SIZE;
			ipaddr_t end = ipa_add(begin, size - 1);

			if (size == 0 || size > UINT64_MAX - ipa_addr(begin)) {
				dlog_verbose(
					"Invalid page count. Addr: %x "
					"page_count: %x\n",
					begin, page_count);
				return false;
			}

			/*
			 * Check if current ranges is within begin and end, as
			 * well as the reverse. This should help optimize the
			 * loop, and reduce the number of iterations.
			 */
			if (is_memory_range_within(begin, end, current_begin,
						   current_end) ||
			    is_memory_range_within(current_begin, current_end,
						   begin, end)) {
				dlog_verbose(
					"Overlapping memory ranges: %#x - %#x "
					"with %#x - %#x\n",
					ipa_addr(begin), ipa_addr(end),
					ipa_addr(current_begin),
					ipa_addr(current_end));
				return true;
			}
		}
	}

	return false;
}

/**
 * Validates and prepares memory to be sent from the calling VM to another.
 *
 * This function requires the calling context to hold the <from> VM lock.
 *
 * Returns:
 *  In case of error, one of the following values is returned:
 *   1) FFA_INVALID_PARAMETERS - The endpoint provided parameters were
 *     erroneous;
 *   2) FFA_NO_MEMORY - Hafnium did not have sufficient memory to complete the
 *     request.
 *   3) FFA_DENIED - The sender doesn't have sufficient access to send the
 *     memory with the given permissions.
 *  Success is indicated by FFA_SUCCESS.
 */
struct ffa_value ffa_send_check_update(
	struct vm_locked from_locked,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t composite_total_page_count, uint32_t share_func,
	struct ffa_memory_access *receivers, uint32_t receivers_count,
	struct mpool *page_pool, bool clear, uint32_t *orig_from_mode_ret)
{
	uint32_t i;
	uint32_t j;
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;
	uint32_t constituents_total_page_count = 0;

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	for (i = 0; i < fragment_count; ++i) {
		if (!is_aligned(fragments[i], 8)) {
			dlog_verbose("Constituents not aligned.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			constituents_total_page_count +=
				fragments[i][j].page_count;
			if (ffa_memory_check_overlap(
				    fragments, fragment_constituent_counts,
				    fragment_count, i, j)) {
				return ffa_error(FFA_INVALID_PARAMETERS);
			}
		}
	}

	if (constituents_total_page_count != composite_total_page_count) {
		dlog_verbose(
			"Composite page count differs from calculated page "
			"count from constituents.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the sender, ensure that
	 * all constituents of a memory region being shared are at the same
	 * state.
	 */
	ret = ffa_send_check_transition(from_locked, share_func, receivers,
					receivers_count, &orig_from_mode,
					fragments, fragment_constituent_counts,
					fragment_count, &from_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition for send.\n");
		return ret;
	}

	if (orig_from_mode_ret != NULL) {
		*orig_from_mode_ret = orig_from_mode;
	}

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if the
	 * clear fails.
	 */
	mpool_init_with_fallback(&local_page_pool, page_pool);

	/*
	 * First reserve all required memory for the new page table entries
	 * without committing, to make sure the entire operation will succeed
	 * without exhausting the page pool.
	 */
	if (!ffa_region_group_identity_map(
		    from_locked, fragments, fragment_constituent_counts,
		    fragment_count, from_mode, page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/*
	 * Update the mapping for the sender. This won't allocate because the
	 * transaction was already prepared above, but may free pages in the
	 * case that a whole block is being unmapped that was previously
	 * partially mapped.
	 */
	CHECK(ffa_region_group_identity_map(
		from_locked, fragments, fragment_constituent_counts,
		fragment_count, from_mode, &local_page_pool, true));

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear &&
	    !ffa_clear_memory_constituents(orig_from_mode, fragments,
					   fragment_constituent_counts,
					   fragment_count, page_pool)) {
		/*
		 * On failure, roll back by returning memory to the sender. This
		 * may allocate pages which were previously freed into
		 * `local_page_pool` by the call above, but will never allocate
		 * more pages than that so can never fail.
		 */
		CHECK(ffa_region_group_identity_map(
			from_locked, fragments, fragment_constituent_counts,
			fragment_count, orig_from_mode, &local_page_pool,
			true));

		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was an
	 * error) or merging entries into blocks where possible (on success).
	 */
	vm_ptable_defrag(from_locked, page_pool);

	return ret;
}

/**
 * Validates and maps memory shared from one VM to another.
 *
 * This function requires the calling context to hold the <to> lock.
 *
 * Returns:
 *  In case of error, one of the following values is returned:
 *   1) FFA_INVALID_PARAMETERS - The endpoint provided parameters were
 *     erroneous;
 *   2) FFA_NO_MEMORY - Hafnium did not have sufficient memory to complete
 *     the request.
 *  Success is indicated by FFA_SUCCESS.
 */
struct ffa_value ffa_retrieve_check_update(
	struct vm_locked to_locked,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t sender_orig_mode, uint32_t share_func, bool clear,
	struct mpool *page_pool)
{
	uint32_t i;
	uint32_t to_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	for (i = 0; i < fragment_count; ++i) {
		if (!is_aligned(fragments[i], 8)) {
			dlog_verbose("Fragment not properly aligned.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	}

	/*
	 * Check if the state transition is lawful for the recipient, and ensure
	 * that all constituents of the memory region being retrieved are at the
	 * same state.
	 */
	ret = ffa_retrieve_check_transition(
		to_locked, share_func, fragments, fragment_constituent_counts,
		fragment_count, sender_orig_mode, &to_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition for retrieve.\n");
		return ret;
	}

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if the
	 * clear fails.
	 */
	mpool_init_with_fallback(&local_page_pool, page_pool);

	/*
	 * First reserve all required memory for the new page table entries in
	 * the recipient page tables without committing, to make sure the entire
	 * operation will succeed without exhausting the page pool.
	 */
	if (!ffa_region_group_identity_map(
		    to_locked, fragments, fragment_constituent_counts,
		    fragment_count, to_mode, page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		dlog_verbose(
			"Insufficient memory to update recipient page "
			"table.\n");
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear &&
	    !ffa_clear_memory_constituents(sender_orig_mode, fragments,
					   fragment_constituent_counts,
					   fragment_count, page_pool)) {
		dlog_verbose("Couldn't clear constituents.\n");
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/*
	 * Complete the transfer by mapping the memory into the recipient. This
	 * won't allocate because the transaction was already prepared above, so
	 * it doesn't need to use the `local_page_pool`.
	 */
	CHECK(ffa_region_group_identity_map(
		to_locked, fragments, fragment_constituent_counts,
		fragment_count, to_mode, page_pool, true));

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was an
	 * error) or merging entries into blocks where possible (on success).
	 */
	vm_ptable_defrag(to_locked, page_pool);

	return ret;
}

static struct ffa_value ffa_relinquish_check_update(
	struct vm_locked from_locked,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	struct mpool *page_pool, bool clear)
{
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;

	ret = ffa_relinquish_check_transition(
		from_locked, &orig_from_mode, fragments,
		fragment_constituent_counts, fragment_count, &from_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition for relinquish.\n");
		return ret;
	}

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if the
	 * clear fails.
	 */
	mpool_init_with_fallback(&local_page_pool, page_pool);

	/*
	 * First reserve all required memory for the new page table entries
	 * without committing, to make sure the entire operation will succeed
	 * without exhausting the page pool.
	 */
	if (!ffa_region_group_identity_map(
		    from_locked, fragments, fragment_constituent_counts,
		    fragment_count, from_mode, page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/*
	 * Update the mapping for the sender. This won't allocate because the
	 * transaction was already prepared above, but may free pages in the
	 * case that a whole block is being unmapped that was previously
	 * partially mapped.
	 */
	CHECK(ffa_region_group_identity_map(
		from_locked, fragments, fragment_constituent_counts,
		fragment_count, from_mode, &local_page_pool, true));

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear &&
	    !ffa_clear_memory_constituents(orig_from_mode, fragments,
					   fragment_constituent_counts,
					   fragment_count, page_pool)) {
		/*
		 * On failure, roll back by returning memory to the sender. This
		 * may allocate pages which were previously freed into
		 * `local_page_pool` by the call above, but will never allocate
		 * more pages than that so can never fail.
		 */
		CHECK(ffa_region_group_identity_map(
			from_locked, fragments, fragment_constituent_counts,
			fragment_count, orig_from_mode, &local_page_pool,
			true));

		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was an
	 * error) or merging entries into blocks where possible (on success).
	 */
	vm_ptable_defrag(from_locked, page_pool);

	return ret;
}

/**
 * Complete a memory sending operation by checking that it is valid, updating
 * the sender page table, and then either marking the share state as having
 * completed sending (on success) or freeing it (on failure).
 *
 * Returns FFA_SUCCESS with the handle encoded, or the relevant FFA_ERROR.
 */
struct ffa_value ffa_memory_send_complete(
	struct vm_locked from_locked, struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state, struct mpool *page_pool,
	uint32_t *orig_from_mode_ret)
{
	struct ffa_memory_region *memory_region = share_state->memory_region;
	struct ffa_composite_memory_region *composite;
	struct ffa_value ret;

	/* Lock must be held. */
	assert(share_states.share_states != NULL);
	assert(memory_region != NULL);
	composite = ffa_memory_region_get_composite(memory_region, 0);
	assert(composite != NULL);

	/* Check that state is valid in sender page table and update. */
	ret = ffa_send_check_update(
		from_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, composite->page_count,
		share_state->share_func, memory_region->receivers,
		memory_region->receiver_count, page_pool,
		memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR,
		orig_from_mode_ret);
	if (ret.func != FFA_SUCCESS_32) {
		/*
		 * Free share state, it failed to send so it can't be retrieved.
		 */
		dlog_verbose("%s: failed to send check update: %s(%s)\n",
			     __func__, ffa_func_name(ret.func),
			     ffa_error_name(ffa_error_code(ret)));
		share_state_free(share_states, share_state, page_pool);
		return ret;
	}

	share_state->sending_complete = true;
	dlog_verbose("%s: marked sending complete.\n", __func__);

	return ffa_mem_success(share_state->memory_region->handle);
}

/**
 * Check that the memory attributes match Hafnium expectations:
 * Normal Memory, Inner shareable, Write-Back Read-Allocate
 * Write-Allocate Cacheable.
 */
static struct ffa_value ffa_memory_attributes_validate(
	ffa_memory_attributes_t attributes)
{
	enum ffa_memory_type memory_type;
	enum ffa_memory_cacheability cacheability;
	enum ffa_memory_shareability shareability;

	memory_type = ffa_get_memory_type_attr(attributes);
	if (memory_type != FFA_MEMORY_NORMAL_MEM) {
		dlog_verbose("Invalid memory type %#x, expected %#x.\n",
			     memory_type, FFA_MEMORY_NORMAL_MEM);
		return ffa_error(FFA_DENIED);
	}

	cacheability = ffa_get_memory_cacheability_attr(attributes);
	if (cacheability != FFA_MEMORY_CACHE_WRITE_BACK) {
		dlog_verbose("Invalid cacheability %#x, expected %#x.\n",
			     cacheability, FFA_MEMORY_CACHE_WRITE_BACK);
		return ffa_error(FFA_DENIED);
	}

	shareability = ffa_get_memory_shareability_attr(attributes);
	if (shareability != FFA_MEMORY_INNER_SHAREABLE) {
		dlog_verbose("Invalid shareability %#x, expected #%x.\n",
			     shareability, FFA_MEMORY_INNER_SHAREABLE);
		return ffa_error(FFA_DENIED);
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Check that the given `memory_region` represents a valid memory send request
 * of the given `share_func` type, return the clear flag and permissions via the
 * respective output parameters, and update the permissions if necessary.
 *
 * Returns FFA_SUCCESS if the request was valid, or the relevant FFA_ERROR if
 * not.
 */
struct ffa_value ffa_memory_send_validate(
	struct vm_locked from_locked, struct ffa_memory_region *memory_region,
	uint32_t memory_share_length, uint32_t fragment_length,
	uint32_t share_func)
{
	struct ffa_composite_memory_region *composite;
	uint64_t receivers_end;
	uint64_t min_length;
	uint32_t composite_memory_region_offset;
	uint32_t constituents_start;
	uint32_t constituents_length;
	enum ffa_data_access data_access;
	enum ffa_instruction_access instruction_access;
	enum ffa_memory_security security_state;
	struct ffa_value ret;
	const size_t minimum_first_fragment_length =
		(sizeof(struct ffa_memory_region) +
		 sizeof(struct ffa_memory_access) +
		 sizeof(struct ffa_composite_memory_region));

	if (fragment_length < minimum_first_fragment_length) {
		dlog_verbose("Fragment length %u too short (min %u).\n",
			     (size_t)fragment_length,
			     minimum_first_fragment_length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	static_assert(sizeof(struct ffa_memory_region_constituent) == 16,
		      "struct ffa_memory_region_constituent must be 16 bytes");
	if (!is_aligned(fragment_length,
			sizeof(struct ffa_memory_region_constituent)) ||
	    !is_aligned(memory_share_length,
			sizeof(struct ffa_memory_region_constituent))) {
		dlog_verbose(
			"Fragment length %u or total length %u"
			" is not 16-byte aligned.\n",
			fragment_length, memory_share_length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (fragment_length > memory_share_length) {
		dlog_verbose(
			"Fragment length %u greater than total length %u.\n",
			(size_t)fragment_length, (size_t)memory_share_length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	assert(memory_region->receivers_offset ==
	       offsetof(struct ffa_memory_region, receivers));
	assert(memory_region->memory_access_desc_size ==
	       sizeof(struct ffa_memory_access));

	/* The sender must match the caller. */
	if ((!vm_id_is_current_world(from_locked.vm->id) &&
	     vm_id_is_current_world(memory_region->sender)) ||
	    (vm_id_is_current_world(from_locked.vm->id) &&
	     memory_region->sender != from_locked.vm->id)) {
		dlog_verbose("Invalid memory sender ID.\n");
		return ffa_error(FFA_DENIED);
	}

	if (memory_region->receiver_count <= 0) {
		dlog_verbose("No receivers!\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Ensure that the composite header is within the memory bounds and
	 * doesn't overlap the first part of the message.  Cast to uint64_t
	 * to prevent overflow.
	 */
	receivers_end = ((uint64_t)sizeof(struct ffa_memory_access) *
			 (uint64_t)memory_region->receiver_count) +
			sizeof(struct ffa_memory_region);
	min_length = receivers_end +
		     sizeof(struct ffa_composite_memory_region) +
		     sizeof(struct ffa_memory_region_constituent);
	if (min_length > memory_share_length) {
		dlog_verbose("Share too short: got %u but minimum is %u.\n",
			     (size_t)memory_share_length, (size_t)min_length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	composite_memory_region_offset =
		memory_region->receivers[0].composite_memory_region_offset;

	/*
	 * Check that the composite memory region descriptor is after the access
	 * descriptors, is at least 16-byte aligned, and fits in the first
	 * fragment.
	 */
	if ((composite_memory_region_offset < receivers_end) ||
	    (composite_memory_region_offset % 16 != 0) ||
	    (composite_memory_region_offset >
	     fragment_length - sizeof(struct ffa_composite_memory_region))) {
		dlog_verbose(
			"Invalid composite memory region descriptor offset "
			"%u.\n",
			(size_t)composite_memory_region_offset);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Compute the start of the constituent regions.  Already checked
	 * to be not more than fragment_length and thus not more than
	 * memory_share_length.
	 */
	constituents_start = composite_memory_region_offset +
			     sizeof(struct ffa_composite_memory_region);
	constituents_length = memory_share_length - constituents_start;

	/*
	 * Check that the number of constituents is consistent with the length
	 * of the constituent region.
	 */
	composite = ffa_memory_region_get_composite(memory_region, 0);
	if ((constituents_length %
		     sizeof(struct ffa_memory_region_constituent) !=
	     0) ||
	    ((constituents_length /
	      sizeof(struct ffa_memory_region_constituent)) !=
	     composite->constituent_count)) {
		dlog_verbose("Invalid length %u or composite offset %u.\n",
			     (size_t)memory_share_length,
			     (size_t)composite_memory_region_offset);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if (fragment_length < memory_share_length &&
	    fragment_length < HF_MAILBOX_SIZE) {
		dlog_warning(
			"Initial fragment length %d smaller than mailbox "
			"size.\n",
			fragment_length);
	}

	/*
	 * Clear is not allowed for memory sharing, as the sender still has
	 * access to the memory.
	 */
	if ((memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR) &&
	    share_func == FFA_MEM_SHARE_32) {
		dlog_verbose("Memory can't be cleared while being shared.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* No other flags are allowed/supported here. */
	if (memory_region->flags & ~FFA_MEMORY_REGION_FLAG_CLEAR) {
		dlog_verbose("Invalid flags %#x.\n", memory_region->flags);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Check that the permissions are valid, for each specified receiver. */
	for (uint32_t i = 0U; i < memory_region->receiver_count; i++) {
		ffa_memory_access_permissions_t permissions =
			memory_region->receivers[i]
				.receiver_permissions.permissions;
		ffa_id_t receiver_id = memory_region->receivers[i]
					       .receiver_permissions.receiver;

		if (memory_region->sender == receiver_id) {
			dlog_verbose("Can't share memory with itself.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}

		for (uint32_t j = i + 1; j < memory_region->receiver_count;
		     j++) {
			if (receiver_id ==
			    memory_region->receivers[j]
				    .receiver_permissions.receiver) {
				dlog_verbose(
					"Repeated receiver(%x) in memory send "
					"operation.\n",
					memory_region->receivers[j]
						.receiver_permissions.receiver);
				return ffa_error(FFA_INVALID_PARAMETERS);
			}
		}

		if (composite_memory_region_offset !=
		    memory_region->receivers[i]
			    .composite_memory_region_offset) {
			dlog_verbose(
				"All ffa_memory_access should point to the "
				"same composite memory region offset.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}

		data_access = ffa_get_data_access_attr(permissions);
		instruction_access =
			ffa_get_instruction_access_attr(permissions);
		if (data_access == FFA_DATA_ACCESS_RESERVED ||
		    instruction_access == FFA_INSTRUCTION_ACCESS_RESERVED) {
			dlog_verbose(
				"Reserved value for receiver permissions "
				"%#x.\n",
				permissions);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		if (instruction_access !=
		    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED) {
			dlog_verbose(
				"Invalid instruction access permissions %#x "
				"for sending memory.\n",
				permissions);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		if (share_func == FFA_MEM_SHARE_32) {
			if (data_access == FFA_DATA_ACCESS_NOT_SPECIFIED) {
				dlog_verbose(
					"Invalid data access permissions %#x "
					"for sharing memory.\n",
					permissions);
				return ffa_error(FFA_INVALID_PARAMETERS);
			}
		}
		if (share_func == FFA_MEM_LEND_32 &&
		    data_access == FFA_DATA_ACCESS_NOT_SPECIFIED) {
			dlog_verbose(
				"Invalid data access permissions %#x for "
				"lending memory.\n",
				permissions);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}

		if (share_func == FFA_MEM_DONATE_32 &&
		    data_access != FFA_DATA_ACCESS_NOT_SPECIFIED) {
			dlog_verbose(
				"Invalid data access permissions %#x for "
				"donating memory.\n",
				permissions);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	}

	/* Memory region attributes NS-Bit MBZ for FFA_MEM_SHARE/LEND/DONATE. */
	security_state =
		ffa_get_memory_security_attr(memory_region->attributes);
	if (security_state != FFA_MEMORY_SECURITY_UNSPECIFIED) {
		dlog_verbose(
			"Invalid security state for memory share operation.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * If a memory donate or lend with single borrower, the memory type
	 * shall not be specified by the sender.
	 */
	if (share_func == FFA_MEM_DONATE_32 ||
	    (share_func == FFA_MEM_LEND_32 &&
	     memory_region->receiver_count == 1)) {
		if (ffa_get_memory_type_attr(memory_region->attributes) !=
		    FFA_MEMORY_NOT_SPECIFIED_MEM) {
			dlog_verbose(
				"Memory type shall not be specified by "
				"sender.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	} else {
		/*
		 * Check that sender's memory attributes match Hafnium
		 * expectations: Normal Memory, Inner shareable, Write-Back
		 * Read-Allocate Write-Allocate Cacheable.
		 */
		ret = ffa_memory_attributes_validate(memory_region->attributes);
		if (ret.func != FFA_SUCCESS_32) {
			return ret;
		}
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Gets the share state for continuing an operation to donate, lend or share
 * memory, and checks that it is a valid request.
 *
 * Returns FFA_SUCCESS if the request was valid, or the relevant FFA_ERROR if
 * not.
 */
struct ffa_value ffa_memory_send_continue_validate(
	struct share_states_locked share_states, ffa_memory_handle_t handle,
	struct ffa_memory_share_state **share_state_ret, ffa_id_t from_vm_id,
	struct mpool *page_pool)
{
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;

	assert(share_state_ret != NULL);

	/*
	 * Look up the share state by handle and make sure that the VM ID
	 * matches.
	 */
	share_state = get_share_state(share_states, handle);
	if (!share_state) {
		dlog_verbose(
			"Invalid handle %#x for memory send continuation.\n",
			handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	memory_region = share_state->memory_region;

	if (vm_id_is_current_world(from_vm_id) &&
	    memory_region->sender != from_vm_id) {
		dlog_verbose("Invalid sender %d.\n", memory_region->sender);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (share_state->sending_complete) {
		dlog_verbose(
			"Sending of memory handle %#x is already complete.\n",
			handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (share_state->fragment_count == MAX_FRAGMENTS) {
		/*
		 * Log a warning as this is a sign that MAX_FRAGMENTS should
		 * probably be increased.
		 */
		dlog_warning(
			"Too many fragments for memory share with handle %#x; "
			"only %d supported.\n",
			handle, MAX_FRAGMENTS);
		/* Free share state, as it's not possible to complete it. */
		share_state_free(share_states, share_state, page_pool);
		return ffa_error(FFA_NO_MEMORY);
	}

	*share_state_ret = share_state;

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Checks if there is at least one receiver from the other world.
 */
bool memory_region_receivers_from_other_world(
	struct ffa_memory_region *memory_region)
{
	for (uint32_t i = 0; i < memory_region->receiver_count; i++) {
		ffa_id_t receiver = memory_region->receivers[i]
					    .receiver_permissions.receiver;
		if (!vm_id_is_current_world(receiver)) {
			return true;
		}
	}
	return false;
}

/**
 * Validates a call to donate, lend or share memory in which Hafnium is the
 * designated allocator of the memory handle. In practice, this also means
 * Hafnium is responsible for managing the state structures for the transaction.
 * If Hafnium is the SPMC, it should allocate the memory handle when either the
 * sender is an SP or there is at least one borrower that is an SP.
 * If Hafnium is the hypervisor, it should allocate the memory handle when
 * operation involves only NWd VMs.
 *
 * If validation goes well, Hafnium updates the stage-2 page tables of the
 * sender. Validation consists of checking if the message length and number of
 * memory region constituents match, and if the transition is valid for the
 * type of memory sending operation.
 *
 * Assumes that the caller has already found and locked the sender VM and copied
 * the memory region descriptor from the sender's TX buffer to a freshly
 * allocated page from Hafnium's internal pool. The caller must have also
 * validated that the receiver VM ID is valid.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
struct ffa_value ffa_memory_send(struct vm_locked from_locked,
				 struct ffa_memory_region *memory_region,
				 uint32_t memory_share_length,
				 uint32_t fragment_length, uint32_t share_func,
				 struct mpool *page_pool)
{
	struct ffa_value ret;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(from_locked, memory_region,
				       memory_share_length, fragment_length,
				       share_func);
	if (ret.func != FFA_SUCCESS_32) {
		mpool_free(page_pool, memory_region);
		return ret;
	}

	/* Set flag for share function, ready to be retrieved later. */
	switch (share_func) {
	case FFA_MEM_SHARE_32:
		memory_region->flags |=
			FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE;
		break;
	case FFA_MEM_LEND_32:
		memory_region->flags |= FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND;
		break;
	case FFA_MEM_DONATE_32:
		memory_region->flags |=
			FFA_MEMORY_REGION_TRANSACTION_TYPE_DONATE;
		break;
	}

	share_states = share_states_lock();
	/*
	 * Allocate a share state before updating the page table. Otherwise if
	 * updating the page table succeeded but allocating the share state
	 * failed then it would leave the memory in a state where nobody could
	 * get it back.
	 */
	share_state = allocate_share_state(share_states, share_func,
					   memory_region, fragment_length,
					   FFA_MEMORY_HANDLE_INVALID);
	if (!share_state) {
		dlog_verbose("Failed to allocate share state.\n");
		mpool_free(page_pool, memory_region);
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	if (fragment_length == memory_share_length) {
		/* No more fragments to come, everything fit in one message. */
		ret = ffa_memory_send_complete(
			from_locked, share_states, share_state, page_pool,
			&(share_state->sender_orig_mode));
	} else {
		/*
		 * Use sender ID from 'memory_region' assuming
		 * that at this point it has been validated:
		 * - MBZ at virtual FF-A instance.
		 */
		ffa_id_t sender_to_ret =
			(from_locked.vm->id == HF_OTHER_WORLD_ID)
				? memory_region->sender
				: 0;
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)memory_region->handle,
			.arg2 = (uint32_t)(memory_region->handle >> 32),
			.arg3 = fragment_length,
			.arg4 = (uint32_t)(sender_to_ret & 0xffff) << 16};
	}

out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

/**
 * Continues an operation to donate, lend or share memory to a VM from current
 * world. If this is the last fragment then checks that the transition is valid
 * for the type of memory sending operation and updates the stage-2 page tables
 * of the sender.
 *
 * Assumes that the caller has already found and locked the sender VM and copied
 * the memory region descriptor from the sender's TX buffer to a freshly
 * allocated page from Hafnium's internal pool.
 *
 * This function takes ownership of the `fragment` passed in; it must not be
 * freed by the caller.
 */
struct ffa_value ffa_memory_send_continue(struct vm_locked from_locked,
					  void *fragment,
					  uint32_t fragment_length,
					  ffa_memory_handle_t handle,
					  struct mpool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;

	CHECK(is_aligned(fragment,
			 alignof(struct ffa_memory_region_constituent)));
	if (fragment_length % sizeof(struct ffa_memory_region_constituent) !=
	    0) {
		dlog_verbose("Fragment length %u misaligned.\n",
			     fragment_length);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_free_fragment;
	}

	ret = ffa_memory_send_continue_validate(share_states, handle,
						&share_state,
						from_locked.vm->id, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_free_fragment;
	}
	memory_region = share_state->memory_region;

	if (memory_region_receivers_from_other_world(memory_region)) {
		dlog_error(
			"Got hypervisor-allocated handle for memory send to "
			"other world. This should never happen, and indicates "
			"a bug in "
			"EL3 code.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_free_fragment;
	}

	/* Add this fragment. */
	share_state->fragments[share_state->fragment_count] = fragment;
	share_state->fragment_constituent_counts[share_state->fragment_count] =
		fragment_length / sizeof(struct ffa_memory_region_constituent);
	share_state->fragment_count++;

	/* Check whether the memory send operation is now ready to complete. */
	if (share_state_sending_complete(share_states, share_state)) {
		ret = ffa_memory_send_complete(
			from_locked, share_states, share_state, page_pool,
			&(share_state->sender_orig_mode));
	} else {
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)handle,
			.arg2 = (uint32_t)(handle >> 32),
			.arg3 = share_state_next_fragment_offset(share_states,
								 share_state)};
	}
	goto out;

out_free_fragment:
	mpool_free(page_pool, fragment);

out:
	share_states_unlock(&share_states);
	return ret;
}

/** Clean up after the receiver has finished retrieving a memory region. */
static void ffa_memory_retrieve_complete(
	struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state, struct mpool *page_pool)
{
	if (share_state->share_func == FFA_MEM_DONATE_32) {
		/*
		 * Memory that has been donated can't be relinquished,
		 * so no need to keep the share state around.
		 */
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state for donate.\n");
	}
}

/**
 * Initialises the given memory region descriptor to be used for an
 * `FFA_MEM_RETRIEVE_RESP`, including the given constituents for the first
 * fragment.
 * The memory region descriptor is initialized according to retriever's
 * FF-A version.
 *
 * Returns true on success, or false if the given constituents won't all fit in
 * the first fragment.
 */
static bool ffa_retrieved_memory_region_init(
	void *response, uint32_t ffa_version, size_t response_max_size,
	ffa_id_t sender, ffa_memory_attributes_t attributes,
	ffa_memory_region_flags_t flags, ffa_memory_handle_t handle,
	ffa_id_t receiver_id, ffa_memory_access_permissions_t permissions,
	uint32_t page_count, uint32_t total_constituent_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t fragment_constituent_count, uint32_t *total_length,
	uint32_t *fragment_length)
{
	struct ffa_composite_memory_region *composite_memory_region;
	struct ffa_memory_access *receiver;
	uint32_t i;
	uint32_t constituents_offset;
	uint32_t receiver_count;

	assert(response != NULL);

	if (ffa_version == MAKE_FFA_VERSION(1, 0)) {
		struct ffa_memory_region_v1_0 *retrieve_response =
			(struct ffa_memory_region_v1_0 *)response;

		ffa_memory_region_init_header_v1_0(
			retrieve_response, sender, attributes, flags, handle, 0,
			RECEIVERS_COUNT_IN_RETRIEVE_RESP);

		receiver = &retrieve_response->receivers[0];
		receiver_count = retrieve_response->receiver_count;

		receiver->composite_memory_region_offset =
			sizeof(struct ffa_memory_region_v1_0) +
			receiver_count * sizeof(struct ffa_memory_access);

		composite_memory_region = ffa_memory_region_get_composite_v1_0(
			retrieve_response, 0);
	} else {
		/* Default to FF-A v1.1 version. */
		struct ffa_memory_region *retrieve_response =
			(struct ffa_memory_region *)response;

		ffa_memory_region_init_header(retrieve_response, sender,
					      attributes, flags, handle, 0, 1);

		receiver = &retrieve_response->receivers[0];
		receiver_count = retrieve_response->receiver_count;

		/*
		 * Note that `sizeof(struct_ffa_memory_region)` and
		 * `sizeof(struct ffa_memory_access)` must both be multiples of
		 * 16 (as verified by the asserts in `ffa_memory.c`, so it is
		 * guaranteed that the offset we calculate here is aligned to a
		 * 64-bit boundary and so 64-bit values can be copied without
		 * alignment faults.
		 */
		receiver->composite_memory_region_offset =
			sizeof(struct ffa_memory_region) +
			receiver_count * sizeof(struct ffa_memory_access);

		composite_memory_region =
			ffa_memory_region_get_composite(retrieve_response, 0);
	}

	assert(receiver != NULL);
	assert(composite_memory_region != NULL);

	/*
	 * Initialized here as in memory retrieve responses we currently expect
	 * one borrower to be specified.
	 */
	ffa_memory_access_init_permissions(receiver, receiver_id, 0, 0, flags);
	receiver->receiver_permissions.permissions = permissions;

	composite_memory_region->page_count = page_count;
	composite_memory_region->constituent_count = total_constituent_count;
	composite_memory_region->reserved_0 = 0;

	constituents_offset = receiver->composite_memory_region_offset +
			      sizeof(struct ffa_composite_memory_region);
	if (constituents_offset +
		    fragment_constituent_count *
			    sizeof(struct ffa_memory_region_constituent) >
	    response_max_size) {
		return false;
	}

	for (i = 0; i < fragment_constituent_count; ++i) {
		composite_memory_region->constituents[i] = constituents[i];
	}

	if (total_length != NULL) {
		*total_length =
			constituents_offset +
			composite_memory_region->constituent_count *
				sizeof(struct ffa_memory_region_constituent);
	}
	if (fragment_length != NULL) {
		*fragment_length =
			constituents_offset +
			fragment_constituent_count *
				sizeof(struct ffa_memory_region_constituent);
	}

	return true;
}

/*
 * Gets the receiver's access permissions from 'struct ffa_memory_region' and
 * returns its index in the receiver's array. If receiver's ID doesn't exist
 * in the array, return the region's 'receiver_count'.
 */
uint32_t ffa_memory_region_get_receiver(struct ffa_memory_region *memory_region,
					ffa_id_t receiver)
{
	struct ffa_memory_access *receivers;
	uint32_t i;

	assert(memory_region != NULL);

	receivers = memory_region->receivers;

	for (i = 0U; i < memory_region->receiver_count; i++) {
		if (receivers[i].receiver_permissions.receiver == receiver) {
			break;
		}
	}

	return i;
}

/**
 * Validates the retrieved permissions against those specified by the lender
 * of memory share operation. Optionally can help set the permissions to be used
 * for the S2 mapping, through the `permissions` argument.
 * Returns FFA_SUCCESS if all the fields are valid. FFA_ERROR, with error code:
 * - FFA_INVALID_PARAMETERS -> if the fields have invalid values as per the
 * specification for each ABI.
 * - FFA_DENIED -> if the permissions specified by the retriever are not
 *   less permissive than those provided by the sender.
 */
static struct ffa_value ffa_memory_retrieve_is_memory_access_valid(
	uint32_t share_func, enum ffa_data_access sent_data_access,
	enum ffa_data_access requested_data_access,
	enum ffa_instruction_access sent_instruction_access,
	enum ffa_instruction_access requested_instruction_access,
	ffa_memory_access_permissions_t *permissions, bool multiple_borrowers)
{
	switch (sent_data_access) {
	case FFA_DATA_ACCESS_NOT_SPECIFIED:
	case FFA_DATA_ACCESS_RW:
		if (requested_data_access == FFA_DATA_ACCESS_NOT_SPECIFIED ||
		    requested_data_access == FFA_DATA_ACCESS_RW) {
			if (permissions != NULL) {
				ffa_set_data_access_attr(permissions,
							 FFA_DATA_ACCESS_RW);
			}
			break;
		}
		/* Intentional fall-through. */
	case FFA_DATA_ACCESS_RO:
		if (requested_data_access == FFA_DATA_ACCESS_NOT_SPECIFIED ||
		    requested_data_access == FFA_DATA_ACCESS_RO) {
			if (permissions != NULL) {
				ffa_set_data_access_attr(permissions,
							 FFA_DATA_ACCESS_RO);
			}
			break;
		}
		dlog_verbose(
			"Invalid data access requested; sender specified "
			"permissions %#x but receiver requested %#x.\n",
			sent_data_access, requested_data_access);
		return ffa_error(FFA_DENIED);
	case FFA_DATA_ACCESS_RESERVED:
		panic("Got unexpected FFA_DATA_ACCESS_RESERVED. Should be "
		      "checked before this point.");
	}

	/*
	 * For operations with a single borrower, If it is an FFA_MEMORY_LEND
	 * or FFA_MEMORY_DONATE the retriever should have specifed the
	 * instruction permissions it wishes to receive.
	 */
	switch (share_func) {
	case FFA_MEM_SHARE_32:
		if (requested_instruction_access !=
		    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED) {
			dlog_verbose(
				"%s: for share instruction permissions must "
				"NOT be specified.\n",
				__func__);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		break;
	case FFA_MEM_LEND_32:
		/*
		 * For operations with multiple borrowers only permit XN
		 * permissions, and both Sender and borrower should have used
		 * FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED.
		 */
		if (multiple_borrowers) {
			if (requested_instruction_access !=
			    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED) {
				dlog_verbose(
					"%s: lend/share/donate with multiple "
					"borrowers "
					"instruction permissions must NOT be "
					"specified.\n",
					__func__);
				return ffa_error(FFA_INVALID_PARAMETERS);
			}
			break;
		}
		/* Fall through if the operation targets a single borrower. */
	case FFA_MEM_DONATE_32:
		if (!multiple_borrowers &&
		    requested_instruction_access ==
			    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED) {
			dlog_verbose(
				"%s: for lend/donate with single borrower "
				"instruction permissions must be speficified "
				"by borrower\n",
				__func__);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		break;
	default:
		panic("%s: Wrong func id provided.\n", __func__);
	}

	switch (sent_instruction_access) {
	case FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED:
	case FFA_INSTRUCTION_ACCESS_X:
		if (requested_instruction_access == FFA_INSTRUCTION_ACCESS_X) {
			if (permissions != NULL) {
				ffa_set_instruction_access_attr(
					permissions, FFA_INSTRUCTION_ACCESS_X);
			}
			break;
		}
		/*
		 * Fall through if requested permissions are less
		 * permissive than those provided by the sender.
		 */
	case FFA_INSTRUCTION_ACCESS_NX:
		if (requested_instruction_access ==
			    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED ||
		    requested_instruction_access == FFA_INSTRUCTION_ACCESS_NX) {
			if (permissions != NULL) {
				ffa_set_instruction_access_attr(
					permissions, FFA_INSTRUCTION_ACCESS_NX);
			}
			break;
		}
		dlog_verbose(
			"Invalid instruction access requested; sender "
			"specified permissions %#x but receiver requested "
			"%#x.\n",
			sent_instruction_access, requested_instruction_access);
		return ffa_error(FFA_DENIED);
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		panic("Got unexpected FFA_INSTRUCTION_ACCESS_RESERVED. Should "
		      "be checked before this point.");
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Validate the receivers' permissions in the retrieve request against those
 * specified by the lender.
 * In the `permissions` argument returns the permissions to set at S2 for the
 * caller to the FFA_MEMORY_RETRIEVE_REQ.
 * The function looks into the flag to bypass multiple borrower checks:
 * - If not set returns FFA_SUCCESS if all specified permissions are valid.
 * - If set returns FFA_SUCCESS if the descriptor contains the permissions
 *   to the caller of FFA_MEM_RETRIEVE_REQ and they are valid. Other permissions
 *   are ignored, if provided.
 */
static struct ffa_value ffa_memory_retrieve_validate_memory_access_list(
	struct ffa_memory_region *memory_region,
	struct ffa_memory_region *retrieve_request, ffa_id_t to_vm_id,
	ffa_memory_access_permissions_t *permissions, uint32_t func_id)
{
	uint32_t retrieve_receiver_index;
	bool bypass_multi_receiver_check =
		(retrieve_request->flags &
		 FFA_MEMORY_REGION_FLAG_BYPASS_BORROWERS_CHECK) != 0U;
	const uint32_t region_receiver_count = memory_region->receiver_count;
	struct ffa_value ret;

	assert(permissions != NULL);

	if (!bypass_multi_receiver_check) {
		if (retrieve_request->receiver_count != region_receiver_count) {
			dlog_verbose(
				"Retrieve request should contain same list of "
				"borrowers, as specified by the lender.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	} else {
		if (retrieve_request->receiver_count != 1) {
			dlog_verbose(
				"Set bypass multiple borrower check, receiver "
				"list must be sized 1 (%x)\n",
				memory_region->receiver_count);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	}

	retrieve_receiver_index = retrieve_request->receiver_count;

	/* Should be populated with the permissions of the retriever. */
	*permissions = 0;

	for (uint32_t i = 0U; i < retrieve_request->receiver_count; i++) {
		ffa_memory_access_permissions_t sent_permissions;
		struct ffa_memory_access *current_receiver =
			&retrieve_request->receivers[i];
		ffa_memory_access_permissions_t requested_permissions =
			current_receiver->receiver_permissions.permissions;
		ffa_id_t current_receiver_id =
			current_receiver->receiver_permissions.receiver;
		bool found_to_id = current_receiver_id == to_vm_id;

		if (bypass_multi_receiver_check && !found_to_id) {
			dlog_verbose(
				"Bypass multiple borrower check for id %x.\n",
				current_receiver_id);
			continue;
		}

		/*
		 * Find the current receiver in the transaction descriptor from
		 * sender.
		 */
		uint32_t mem_region_receiver_index =
			ffa_memory_region_get_receiver(memory_region,
						       current_receiver_id);

		if (mem_region_receiver_index ==
		    memory_region->receiver_count) {
			dlog_verbose("%s: receiver %x not found\n", __func__,
				     current_receiver_id);
			return ffa_error(FFA_DENIED);
		}

		sent_permissions =
			memory_region->receivers[mem_region_receiver_index]
				.receiver_permissions.permissions;

		if (found_to_id) {
			retrieve_receiver_index = i;
		}

		/*
		 * Since we are traversing the list of receivers, save the index
		 * of the caller. As it needs to be there.
		 */

		if (current_receiver->composite_memory_region_offset != 0U) {
			dlog_verbose(
				"Retriever specified address ranges not "
				"supported (got offset %d).\n",
				current_receiver
					->composite_memory_region_offset);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}

		/*
		 * Check if retrieve request memory access list is valid:
		 * - The retrieve request complies with the specification.
		 * - Permissions are within those specified by the sender.
		 */
		ret = ffa_memory_retrieve_is_memory_access_valid(
			func_id, ffa_get_data_access_attr(sent_permissions),
			ffa_get_data_access_attr(requested_permissions),
			ffa_get_instruction_access_attr(sent_permissions),
			ffa_get_instruction_access_attr(requested_permissions),
			found_to_id ? permissions : NULL,
			region_receiver_count > 1);
		if (ret.func != FFA_SUCCESS_32) {
			return ret;
		}

		/*
		 * Can't request PM to clear memory if only provided with RO
		 * permissions.
		 */
		if (found_to_id &&
		    (ffa_get_data_access_attr(*permissions) ==
		     FFA_DATA_ACCESS_RO) &&
		    (retrieve_request->flags & FFA_MEMORY_REGION_FLAG_CLEAR) !=
			    0U) {
			dlog_verbose(
				"Receiver has RO permissions can not request "
				"clear.\n");
			return ffa_error(FFA_DENIED);
		}
	}

	if (retrieve_receiver_index == retrieve_request->receiver_count) {
		dlog_verbose(
			"Retrieve request does not contain caller's (%x) "
			"permissions\n",
			to_vm_id);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/*
 * According to section 16.4.3 of FF-A v1.1 EAC0 specification, the hypervisor
 * may issue an FFA_MEM_RETRIEVE_REQ to obtain the memory region description
 * of a pending memory sharing operation whose allocator is the SPM, for
 * validation purposes before forwarding an FFA_MEM_RECLAIM call. In doing so
 * the memory region descriptor of the retrieve request must be zeroed with the
 * exception of the sender ID and handle.
 */
bool is_ffa_memory_retrieve_borrower_request(struct ffa_memory_region *request,
					     struct vm_locked to_locked)
{
	return to_locked.vm->id == HF_HYPERVISOR_VM_ID &&
	       request->attributes == 0U && request->flags == 0U &&
	       request->tag == 0U && request->receiver_count == 0U &&
	       plat_ffa_memory_handle_allocated_by_current_world(
		       request->handle);
}

/*
 * Helper to reset count of fragments retrieved by the hypervisor.
 */
static void ffa_memory_retrieve_complete_from_hyp(
	struct ffa_memory_share_state *share_state)
{
	if (share_state->hypervisor_fragment_count ==
	    share_state->fragment_count) {
		share_state->hypervisor_fragment_count = 0;
	}
}

/**
 * Validate that the memory region descriptor provided by the borrower on
 * FFA_MEM_RETRIEVE_REQ, against saved memory region provided by lender at the
 * memory sharing call.
 */
static struct ffa_value ffa_memory_retrieve_validate(
	ffa_id_t receiver_id, struct ffa_memory_region *retrieve_request,
	struct ffa_memory_region *memory_region, uint32_t *receiver_index,
	uint32_t share_func)
{
	ffa_memory_region_flags_t transaction_type =
		retrieve_request->flags &
		FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK;
	enum ffa_memory_security security_state;

	assert(retrieve_request != NULL);
	assert(memory_region != NULL);
	assert(receiver_index != NULL);
	assert(retrieve_request->sender == memory_region->sender);

	/*
	 * Check that the transaction type expected by the receiver is
	 * correct, if it has been specified.
	 */
	if (transaction_type !=
		    FFA_MEMORY_REGION_TRANSACTION_TYPE_UNSPECIFIED &&
	    transaction_type != (memory_region->flags &
				 FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK)) {
		dlog_verbose(
			"Incorrect transaction type %#x for "
			"FFA_MEM_RETRIEVE_REQ, expected %#x for handle %#x.\n",
			transaction_type,
			memory_region->flags &
				FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK,
			retrieve_request->handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (retrieve_request->tag != memory_region->tag) {
		dlog_verbose(
			"Incorrect tag %d for FFA_MEM_RETRIEVE_REQ, expected "
			"%d for handle %#x.\n",
			retrieve_request->tag, memory_region->tag,
			retrieve_request->handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	*receiver_index =
		ffa_memory_region_get_receiver(memory_region, receiver_id);

	if (*receiver_index == memory_region->receiver_count) {
		dlog_verbose(
			"Incorrect receiver VM ID %d for "
			"FFA_MEM_RETRIEVE_REQ, for handle %#x.\n",
			receiver_id, memory_region->handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if ((retrieve_request->flags &
	     FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_VALID) != 0U) {
		dlog_verbose(
			"Retriever specified 'address range alignment 'hint' "
			"not supported.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if ((retrieve_request->flags &
	     FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_MASK) != 0) {
		dlog_verbose(
			"Bits 8-5 must be zero in memory region's flags "
			"(address range alignment hint not supported).\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if ((retrieve_request->flags & ~0x7FF) != 0U) {
		dlog_verbose(
			"Bits 31-10 must be zero in memory region's flags.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (share_func == FFA_MEM_SHARE_32 &&
	    (retrieve_request->flags &
	     (FFA_MEMORY_REGION_FLAG_CLEAR |
	      FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH)) != 0U) {
		dlog_verbose(
			"Memory Share operation can't clean after relinquish "
			"memory region.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * If the borrower needs the memory to be cleared before mapping
	 * to its address space, the sender should have set the flag
	 * when calling FFA_MEM_LEND/FFA_MEM_DONATE, else return
	 * FFA_DENIED.
	 */
	if ((retrieve_request->flags & FFA_MEMORY_REGION_FLAG_CLEAR) != 0U &&
	    (memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR) == 0U) {
		dlog_verbose(
			"Borrower needs memory cleared. Sender needs to set "
			"flag for clearing memory.\n");
		return ffa_error(FFA_DENIED);
	}

	/* Memory region attributes NS-Bit MBZ for FFA_MEM_RETRIEVE_REQ. */
	security_state =
		ffa_get_memory_security_attr(retrieve_request->attributes);
	if (security_state != FFA_MEMORY_SECURITY_UNSPECIFIED) {
		dlog_verbose(
			"Invalid security state for memory retrieve request "
			"operation.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * If memory type is not specified, bypass validation of memory
	 * attributes in the retrieve request. The retriever is expecting to
	 * obtain this information from the SPMC.
	 */
	if (ffa_get_memory_type_attr(retrieve_request->attributes) ==
	    FFA_MEMORY_NOT_SPECIFIED_MEM) {
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	}

	/*
	 * Ensure receiver's attributes are compatible with how
	 * Hafnium maps memory: Normal Memory, Inner shareable,
	 * Write-Back Read-Allocate Write-Allocate Cacheable.
	 */
	return ffa_memory_attributes_validate(retrieve_request->attributes);
}

struct ffa_value ffa_memory_retrieve(struct vm_locked to_locked,
				     struct ffa_memory_region *retrieve_request,
				     uint32_t retrieve_request_length,
				     struct mpool *page_pool)
{
	uint32_t expected_retrieve_request_length =
		sizeof(struct ffa_memory_region) +
		retrieve_request->receiver_count *
			sizeof(struct ffa_memory_access);
	ffa_memory_handle_t handle = retrieve_request->handle;
	struct ffa_memory_region *memory_region;
	ffa_memory_access_permissions_t permissions = 0;
	uint32_t memory_to_mode;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_composite_memory_region *composite;
	uint32_t total_length;
	uint32_t fragment_length;
	ffa_id_t receiver_id = to_locked.vm->id;
	bool is_send_complete = false;
	ffa_memory_attributes_t attributes;

	dump_share_states();

	if (retrieve_request_length != expected_retrieve_request_length) {
		dlog_verbose(
			"Invalid length for FFA_MEM_RETRIEVE_REQ, expected %d "
			"but was %d.\n",
			expected_retrieve_request_length,
			retrieve_request_length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	share_states = share_states_lock();
	share_state = get_share_state(share_states, handle);
	if (!share_state) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RETRIEVE_REQ.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->sending_complete) {
		dlog_verbose(
			"Memory with handle %#x not fully sent, can't "
			"retrieve.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;

	CHECK(memory_region != NULL);

	if (retrieve_request->sender != memory_region->sender) {
		dlog_verbose(
			"Memory with handle %#x not fully sent, can't "
			"retrieve.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!is_ffa_memory_retrieve_borrower_request(retrieve_request,
						     to_locked)) {
		uint32_t receiver_index;

		/*
		 * The SPMC can only process retrieve requests to memory share
		 * operations with one borrower from the other world. It can't
		 * determine the ID of the NWd VM that invoked the retrieve
		 * request interface call. It relies on the hypervisor to
		 * validate the caller's ID against that provided in the
		 * `receivers` list of the retrieve response.
		 * In case there is only one borrower from the NWd in the
		 * transaction descriptor, record that in the `receiver_id` for
		 * later use, and validate in the retrieve request message.
		 * This limitation is due to the fact SPMC can't determine the
		 * index in the memory share structures state to update.
		 */
		if (to_locked.vm->id == HF_HYPERVISOR_VM_ID) {
			uint32_t other_world_count = 0;

			for (uint32_t i = 0; i < memory_region->receiver_count;
			     i++) {
				receiver_id =
					retrieve_request->receivers[0]
						.receiver_permissions.receiver;
				if (!vm_id_is_current_world(receiver_id)) {
					other_world_count++;
				}
			}
			if (other_world_count > 1) {
				dlog_verbose(
					"Support one receiver from the other "
					"world.\n");
				return ffa_error(FFA_NOT_SUPPORTED);
			}
		}

		/*
		 * Validate retrieve request, according to what was sent by the
		 * sender. Function will output the `receiver_index` from the
		 * provided memory region.
		 */
		ret = ffa_memory_retrieve_validate(
			receiver_id, retrieve_request, memory_region,
			&receiver_index, share_state->share_func);
		if (ret.func != FFA_SUCCESS_32) {
			goto out;
		}

		if (share_state->retrieved_fragment_count[receiver_index] !=
		    0U) {
			dlog_verbose(
				"Memory with handle %#x already retrieved.\n",
				handle);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		/*
		 * Validate the requested permissions against the sent
		 * permissions.
		 * Outputs the permissions to give to retriever at S2
		 * PTs.
		 */
		ret = ffa_memory_retrieve_validate_memory_access_list(
			memory_region, retrieve_request, receiver_id,
			&permissions, share_state->share_func);
		if (ret.func != FFA_SUCCESS_32) {
			goto out;
		}

		memory_to_mode = ffa_memory_permissions_to_mode(
			permissions, share_state->sender_orig_mode);

		ret = ffa_retrieve_check_update(
			to_locked, share_state->fragments,
			share_state->fragment_constituent_counts,
			share_state->fragment_count, memory_to_mode,
			share_state->share_func, false, page_pool);

		if (ret.func != FFA_SUCCESS_32) {
			goto out;
		}

		share_state->retrieved_fragment_count[receiver_index] = 1;
		is_send_complete =
			share_state->retrieved_fragment_count[receiver_index] ==
			share_state->fragment_count;

		share_state->clear_after_relinquish =
			(retrieve_request->flags &
			 FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH) != 0U;

	} else {
		if (share_state->hypervisor_fragment_count != 0U) {
			dlog_verbose(
				"Memory with handle %#x already retrieved by "
				"the hypervisor.\n",
				handle);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		share_state->hypervisor_fragment_count = 1;

		ffa_memory_retrieve_complete_from_hyp(share_state);
	}

	/* VMs acquire the RX buffer from SPMC. */
	CHECK(plat_ffa_acquire_receiver_rx(to_locked, &ret));

	/*
	 * Copy response to RX buffer of caller and deliver the message.
	 * This must be done before the share_state is (possibly) freed.
	 */
	/* TODO: combine attributes from sender and request. */
	composite = ffa_memory_region_get_composite(memory_region, 0);
	/*
	 * Constituents which we received in the first fragment should
	 * always fit in the first fragment we are sending, because the
	 * header is the same size in both cases and we have a fixed
	 * message buffer size. So `ffa_retrieved_memory_region_init`
	 * should never fail.
	 */

	/*
	 * Set the security state in the memory retrieve response attributes
	 * if specified by the target mode.
	 */
	attributes = plat_ffa_memory_security_mode(
		memory_region->attributes, share_state->sender_orig_mode);

	CHECK(ffa_retrieved_memory_region_init(
		to_locked.vm->mailbox.recv, to_locked.vm->ffa_version,
		HF_MAILBOX_SIZE, memory_region->sender, attributes,
		memory_region->flags, handle, receiver_id, permissions,
		composite->page_count, composite->constituent_count,
		share_state->fragments[0],
		share_state->fragment_constituent_counts[0], &total_length,
		&fragment_length));

	to_locked.vm->mailbox.recv_size = fragment_length;
	to_locked.vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	to_locked.vm->mailbox.recv_func = FFA_MEM_RETRIEVE_RESP_32;
	to_locked.vm->mailbox.state = MAILBOX_STATE_FULL;

	if (is_send_complete) {
		ffa_memory_retrieve_complete(share_states, share_state,
					     page_pool);
	}
	ret = (struct ffa_value){.func = FFA_MEM_RETRIEVE_RESP_32,
				 .arg1 = total_length,
				 .arg2 = fragment_length};
out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

/**
 * Determine expected fragment offset according to the FF-A version of
 * the caller.
 */
static uint32_t ffa_memory_retrieve_expected_offset_per_ffa_version(
	struct ffa_memory_region *memory_region,
	uint32_t retrieved_constituents_count, uint32_t ffa_version)
{
	uint32_t expected_fragment_offset;
	uint32_t composite_constituents_offset;

	if (ffa_version == MAKE_FFA_VERSION(1, 1)) {
		/*
		 * Hafnium operates memory regions in FF-A v1.1 format, so we
		 * can retrieve the constituents offset from descriptor.
		 */
		composite_constituents_offset =
			ffa_composite_constituent_offset(memory_region, 0);
	} else if (ffa_version == MAKE_FFA_VERSION(1, 0)) {
		/*
		 * If retriever is FF-A v1.0, determine the composite offset
		 * as it is expected to have been configured in the
		 * retrieve response.
		 */
		composite_constituents_offset =
			sizeof(struct ffa_memory_region_v1_0) +
			RECEIVERS_COUNT_IN_RETRIEVE_RESP *
				sizeof(struct ffa_memory_access) +
			sizeof(struct ffa_composite_memory_region);
	} else {
		panic("%s received an invalid FF-A version.\n", __func__);
	}

	expected_fragment_offset =
		composite_constituents_offset +
		retrieved_constituents_count *
			sizeof(struct ffa_memory_region_constituent) -
		sizeof(struct ffa_memory_access) *
			(memory_region->receiver_count - 1);

	return expected_fragment_offset;
}

struct ffa_value ffa_memory_retrieve_continue(struct vm_locked to_locked,
					      ffa_memory_handle_t handle,
					      uint32_t fragment_offset,
					      ffa_id_t sender_vm_id,
					      struct mpool *page_pool)
{
	struct ffa_memory_region *memory_region;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	uint32_t fragment_index;
	uint32_t retrieved_constituents_count;
	uint32_t i;
	uint32_t expected_fragment_offset;
	uint32_t remaining_constituent_count;
	uint32_t fragment_length;
	uint32_t receiver_index;
	bool continue_ffa_hyp_mem_retrieve_req;

	dump_share_states();

	share_states = share_states_lock();
	share_state = get_share_state(share_states, handle);
	if (!share_state) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_FRAG_RX.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (!share_state->sending_complete) {
		dlog_verbose(
			"Memory with handle %#x not fully sent, can't "
			"retrieve.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * If retrieve request from the hypervisor has been initiated in the
	 * given share_state, continue it, else assume it is a continuation of
	 * retrieve request from a NWd VM.
	 */
	continue_ffa_hyp_mem_retrieve_req =
		(to_locked.vm->id == HF_HYPERVISOR_VM_ID) &&
		(share_state->hypervisor_fragment_count != 0U) &&
		ffa_is_vm_id(sender_vm_id);

	if (!continue_ffa_hyp_mem_retrieve_req) {
		receiver_index = ffa_memory_region_get_receiver(
			memory_region, to_locked.vm->id);

		if (receiver_index == memory_region->receiver_count) {
			dlog_verbose(
				"Caller of FFA_MEM_FRAG_RX (%x) is not a "
				"borrower to memory sharing transaction (%x)\n",
				to_locked.vm->id, handle);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		if (share_state->retrieved_fragment_count[receiver_index] ==
			    0 ||
		    share_state->retrieved_fragment_count[receiver_index] >=
			    share_state->fragment_count) {
			dlog_verbose(
				"Retrieval of memory with handle %#x not yet "
				"started or already completed (%d/%d fragments "
				"retrieved).\n",
				handle,
				share_state->retrieved_fragment_count
					[receiver_index],
				share_state->fragment_count);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		fragment_index =
			share_state->retrieved_fragment_count[receiver_index];
	} else {
		if (share_state->hypervisor_fragment_count == 0 ||
		    share_state->hypervisor_fragment_count >=
			    share_state->fragment_count) {
			dlog_verbose(
				"Retrieve of memory with handle %x not "
				"started from hypervisor.\n",
				handle);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		if (memory_region->sender != sender_vm_id) {
			dlog_verbose(
				"Sender ID (%x) is not as expected for memory "
				"handle %x\n",
				sender_vm_id, handle);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		fragment_index = share_state->hypervisor_fragment_count;

		receiver_index = 0;
	}

	/*
	 * Check that the given fragment offset is correct by counting
	 * how many constituents were in the fragments previously sent.
	 */
	retrieved_constituents_count = 0;
	for (i = 0; i < fragment_index; ++i) {
		retrieved_constituents_count +=
			share_state->fragment_constituent_counts[i];
	}

	CHECK(memory_region->receiver_count > 0);

	expected_fragment_offset =
		ffa_memory_retrieve_expected_offset_per_ffa_version(
			memory_region, retrieved_constituents_count,
			to_locked.vm->ffa_version);

	if (fragment_offset != expected_fragment_offset) {
		dlog_verbose("Fragment offset was %d but expected %d.\n",
			     fragment_offset, expected_fragment_offset);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* VMs acquire the RX buffer from SPMC. */
	CHECK(plat_ffa_acquire_receiver_rx(to_locked, &ret));

	remaining_constituent_count = ffa_memory_fragment_init(
		to_locked.vm->mailbox.recv, HF_MAILBOX_SIZE,
		share_state->fragments[fragment_index],
		share_state->fragment_constituent_counts[fragment_index],
		&fragment_length);
	CHECK(remaining_constituent_count == 0);
	to_locked.vm->mailbox.recv_size = fragment_length;
	to_locked.vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	to_locked.vm->mailbox.recv_func = FFA_MEM_FRAG_TX_32;
	to_locked.vm->mailbox.state = MAILBOX_STATE_FULL;

	if (!continue_ffa_hyp_mem_retrieve_req) {
		share_state->retrieved_fragment_count[receiver_index]++;
		if (share_state->retrieved_fragment_count[receiver_index] ==
		    share_state->fragment_count) {
			ffa_memory_retrieve_complete(share_states, share_state,
						     page_pool);
		}
	} else {
		share_state->hypervisor_fragment_count++;

		ffa_memory_retrieve_complete_from_hyp(share_state);
	}
	ret = (struct ffa_value){.func = FFA_MEM_FRAG_TX_32,
				 .arg1 = (uint32_t)handle,
				 .arg2 = (uint32_t)(handle >> 32),
				 .arg3 = fragment_length};

out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

struct ffa_value ffa_memory_relinquish(
	struct vm_locked from_locked,
	struct ffa_mem_relinquish *relinquish_request, struct mpool *page_pool)
{
	ffa_memory_handle_t handle = relinquish_request->handle;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;
	bool clear;
	struct ffa_value ret;
	uint32_t receiver_index;
	bool receivers_relinquished_memory;

	if (relinquish_request->endpoint_count != 1) {
		dlog_verbose(
			"Stream endpoints not supported (got %d "
			"endpoints on FFA_MEM_RELINQUISH, expected 1).\n",
			relinquish_request->endpoint_count);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (relinquish_request->endpoints[0] != from_locked.vm->id) {
		dlog_verbose(
			"VM ID %d in relinquish message doesn't match "
			"calling VM ID %d.\n",
			relinquish_request->endpoints[0], from_locked.vm->id);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	dump_share_states();

	share_states = share_states_lock();
	share_state = get_share_state(share_states, handle);
	if (!share_state) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RELINQUISH.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->sending_complete) {
		dlog_verbose(
			"Memory with handle %#x not fully sent, can't "
			"relinquish.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	receiver_index = ffa_memory_region_get_receiver(memory_region,
							from_locked.vm->id);

	if (receiver_index == memory_region->receiver_count) {
		dlog_verbose(
			"VM ID %d tried to relinquish memory region "
			"with handle %#x and it is not a valid borrower.\n",
			from_locked.vm->id, handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (share_state->retrieved_fragment_count[receiver_index] !=
	    share_state->fragment_count) {
		dlog_verbose(
			"Memory with handle %#x not yet fully "
			"retrieved, "
			"receiver %x can't relinquish.\n",
			handle, from_locked.vm->id);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Either clear if requested in relinquish call, or in a retrieve
	 * request from one of the borrowers.
	 */
	receivers_relinquished_memory = true;

	for (uint32_t i = 0; i < memory_region->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			&memory_region->receivers[i];

		if (receiver->receiver_permissions.receiver ==
		    from_locked.vm->id) {
			continue;
		}

		if (share_state->retrieved_fragment_count[i] != 0U) {
			receivers_relinquished_memory = false;
			break;
		}
	}

	clear = receivers_relinquished_memory &&
		(share_state->clear_after_relinquish ||
		 (relinquish_request->flags & FFA_MEMORY_REGION_FLAG_CLEAR) !=
			 0U);

	/*
	 * Clear is not allowed for memory that was shared, as the
	 * original sender still has access to the memory.
	 */
	if (clear && share_state->share_func == FFA_MEM_SHARE_32) {
		dlog_verbose("Memory which was shared can't be cleared.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	ret = ffa_relinquish_check_update(
		from_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, page_pool, clear);

	if (ret.func == FFA_SUCCESS_32) {
		/*
		 * Mark memory handle as not retrieved, so it can be
		 * reclaimed (or retrieved again).
		 */
		share_state->retrieved_fragment_count[receiver_index] = 0;
	}

out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

/**
 * Validates that the reclaim transition is allowed for the given
 * handle, updates the page table of the reclaiming VM, and frees the
 * internal state associated with the handle.
 */
struct ffa_value ffa_memory_reclaim(struct vm_locked to_locked,
				    ffa_memory_handle_t handle,
				    ffa_memory_region_flags_t flags,
				    struct mpool *page_pool)
{
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;
	struct ffa_value ret;

	dump_share_states();

	share_states = share_states_lock();

	share_state = get_share_state(share_states, handle);
	if (!share_state) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RECLAIM.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}
	memory_region = share_state->memory_region;

	CHECK(memory_region != NULL);

	if (vm_id_is_current_world(to_locked.vm->id) &&
	    to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %#x attempted to reclaim memory handle %#x "
			"originally sent by VM %#x.\n",
			to_locked.vm->id, handle, memory_region->sender);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->sending_complete) {
		dlog_verbose(
			"Memory with handle %#x not fully sent, can't "
			"reclaim.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	for (uint32_t i = 0; i < memory_region->receiver_count; i++) {
		if (share_state->retrieved_fragment_count[i] != 0) {
			dlog_verbose(
				"Tried to reclaim memory handle %#x "
				"that has not been relinquished by all "
				"borrowers(%x).\n",
				handle,
				memory_region->receivers[i]
					.receiver_permissions.receiver);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}
	}

	ret = ffa_retrieve_check_update(
		to_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, share_state->sender_orig_mode,
		FFA_MEM_RECLAIM_32, flags & FFA_MEM_RECLAIM_CLEAR, page_pool);

	if (ret.func == FFA_SUCCESS_32) {
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state after successful reclaim.\n");
	}

out:
	share_states_unlock(&share_states);
	return ret;
}
