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

#include "hf/ffa_memory.h"

#include "hf/arch/tee.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa_internal.h"
#include "hf/mpool.h"
#include "hf/std.h"
#include "hf/vm.h"

/** The maximum number of recipients a memory region may be sent to. */
#define MAX_MEM_SHARE_RECIPIENTS 1

/**
 * The maximum number of memory sharing handles which may be active at once. A
 * DONATE handle is active from when it is sent to when it is retrieved; a SHARE
 * or LEND handle is active from when it is sent to when it is reclaimed.
 */
#define MAX_MEM_SHARES 100

static_assert(sizeof(struct ffa_memory_region_constituent) % 16 == 0,
	      "struct ffa_memory_region_constituent must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct ffa_composite_memory_region) % 16 == 0,
	      "struct ffa_composite_memory_region must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct ffa_memory_region_attributes) == 4,
	      "struct ffa_memory_region_attributes must be 4bytes long.");
static_assert(sizeof(struct ffa_memory_access) % 16 == 0,
	      "struct ffa_memory_access must be a multiple of 16 bytes long.");
static_assert(sizeof(struct ffa_memory_region) % 16 == 0,
	      "struct ffa_memory_region must be a multiple of 16 bytes long.");
static_assert(sizeof(struct ffa_mem_relinquish) % 16 == 0,
	      "struct ffa_mem_relinquish must be a multiple of 16 "
	      "bytes long.");

struct ffa_memory_share_state {
	/**
	 * The memory region being shared, or NULL if this share state is
	 * unallocated.
	 */
	struct ffa_memory_region *memory_region;

	/**
	 * The FF-A function used for sharing the memory. Must be one of
	 * FFA_MEM_DONATE_32, FFA_MEM_LEND_32 or FFA_MEM_SHARE_32 if the
	 * share state is allocated, or 0.
	 */
	uint32_t share_func;

	/**
	 * Whether each recipient has retrieved the memory region yet. The order
	 * of this array matches the order of the attribute descriptors in the
	 * memory region descriptor. Any entries beyond the attribute_count will
	 * always be false.
	 */
	bool retrieved[MAX_MEM_SHARE_RECIPIENTS];
};

/**
 * Encapsulates the set of share states while the `share_states_lock` is held.
 */
struct share_states_locked {
	struct ffa_memory_share_state *share_states;
};

/**
 * All access to members of a `struct ffa_memory_share_state` must be guarded
 * by this lock.
 */
static struct spinlock share_states_lock_instance = SPINLOCK_INIT;
static struct ffa_memory_share_state share_states[MAX_MEM_SHARES];

/**
 * Initialises the next available `struct ffa_memory_share_state` and sets
 * `handle` to its handle. Returns true on succes or false if none are
 * available.
 */
static bool allocate_share_state(uint32_t share_func,
				 struct ffa_memory_region *memory_region,
				 ffa_memory_handle_t *handle)
{
	uint64_t i;

	CHECK(memory_region != NULL);

	sl_lock(&share_states_lock_instance);
	for (i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states[i].share_func == 0) {
			uint32_t j;
			struct ffa_memory_share_state *allocated_state =
				&share_states[i];
			allocated_state->share_func = share_func;
			allocated_state->memory_region = memory_region;
			for (j = 0; j < MAX_MEM_SHARE_RECIPIENTS; ++j) {
				allocated_state->retrieved[j] = false;
			}
			*handle = i | FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
			sl_unlock(&share_states_lock_instance);
			return true;
		}
	}

	sl_unlock(&share_states_lock_instance);
	return false;
}

/** Locks the share states lock. */
struct share_states_locked share_states_lock(void)
{
	sl_lock(&share_states_lock_instance);

	return (struct share_states_locked){.share_states = share_states};
}

/** Unlocks the share states lock. */
static void share_states_unlock(struct share_states_locked *share_states)
{
	CHECK(share_states->share_states != NULL);
	share_states->share_states = NULL;
	sl_unlock(&share_states_lock_instance);
}

/**
 * If the given handle is a valid handle for an allocated share state then takes
 * the lock, initialises `share_state_locked` to point to the share state and
 * returns true. Otherwise returns false and doesn't take the lock.
 */
static bool get_share_state(struct share_states_locked share_states,
			    ffa_memory_handle_t handle,
			    struct ffa_memory_share_state **share_state_ret)
{
	struct ffa_memory_share_state *share_state;
	uint32_t index = handle & ~FFA_MEMORY_HANDLE_ALLOCATOR_MASK;

	if (index >= MAX_MEM_SHARES) {
		return false;
	}

	share_state = &share_states.share_states[index];

	if (share_state->share_func == 0) {
		return false;
	}

	*share_state_ret = share_state;
	return true;
}

/** Marks a share state as unallocated. */
static void share_state_free(struct share_states_locked share_states,
			     struct ffa_memory_share_state *share_state,
			     struct mpool *page_pool)
{
	CHECK(share_states.share_states != NULL);
	share_state->share_func = 0;
	mpool_free(page_pool, share_state->memory_region);
	share_state->memory_region = NULL;
}

/**
 * Marks the share state with the given handle as unallocated, or returns false
 * if the handle was invalid.
 */
static bool share_state_free_handle(ffa_memory_handle_t handle,
				    struct mpool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct ffa_memory_share_state *share_state;

	if (!get_share_state(share_states, handle, &share_state)) {
		share_states_unlock(&share_states);
		return false;
	}

	share_state_free(share_states, share_state, page_pool);
	share_states_unlock(&share_states);

	return true;
}

static void dump_memory_region(struct ffa_memory_region *memory_region)
{
	uint32_t i;

	if (LOG_LEVEL < LOG_LEVEL_VERBOSE) {
		return;
	}

	dlog("from VM %d, attributes %#x, flags %#x, handle %#x, tag %d, to %d "
	     "recipients [",
	     memory_region->sender, memory_region->attributes,
	     memory_region->flags, memory_region->handle, memory_region->tag,
	     memory_region->receiver_count);
	for (i = 0; i < memory_region->receiver_count; ++i) {
		if (i != 0) {
			dlog(", ");
		}
		dlog("VM %d: %#x (offset %d)",
		     memory_region->receivers[i].receiver_permissions.receiver,
		     memory_region->receivers[i]
			     .receiver_permissions.permissions,
		     memory_region->receivers[i]
			     .composite_memory_region_offset);
	}
	dlog("]");
}

static void dump_share_states(void)
{
	uint32_t i;

	if (LOG_LEVEL < LOG_LEVEL_VERBOSE) {
		return;
	}

	dlog("Current share states:\n");
	sl_lock(&share_states_lock_instance);
	for (i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states[i].share_func != 0) {
			dlog("%d: ", i);
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
			dlog(" (");
			dump_memory_region(share_states[i].memory_region);
			if (share_states[i].retrieved[0]) {
				dlog("): retrieved\n");
			} else {
				dlog("): not retrieved\n");
			}
			break;
		}
	}
	sl_unlock(&share_states_lock_instance);
}

/* TODO: Add device attributes: GRE, cacheability, shareability. */
static inline uint32_t ffa_memory_permissions_to_mode(
	ffa_memory_access_permissions_t permissions)
{
	uint32_t mode = 0;

	switch (ffa_get_data_access_attr(permissions)) {
	case FFA_DATA_ACCESS_RO:
		mode = MM_MODE_R;
		break;
	case FFA_DATA_ACCESS_RW:
	case FFA_DATA_ACCESS_NOT_SPECIFIED:
		mode = MM_MODE_R | MM_MODE_W;
		break;
	case FFA_DATA_ACCESS_RESERVED:
		panic("Tried to convert FFA_DATA_ACCESS_RESERVED.");
	}

	switch (ffa_get_instruction_access_attr(permissions)) {
	case FFA_INSTRUCTION_ACCESS_NX:
		break;
	case FFA_INSTRUCTION_ACCESS_X:
	case FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED:
		mode |= MM_MODE_X;
		break;
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		panic("Tried to convert FFA_INSTRUCTION_ACCESS_RESVERVED.");
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
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count)
{
	uint32_t i;

	if (constituent_count == 0) {
		/*
		 * Fail if there are no constituents. Otherwise we would get an
		 * uninitialised *orig_mode.
		 */
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	for (i = 0; i < constituent_count; ++i) {
		ipaddr_t begin = ipa_init(constituents[i].address);
		size_t size = constituents[i].page_count * PAGE_SIZE;
		ipaddr_t end = ipa_add(begin, size);
		uint32_t current_mode;

		/* Fail if addresses are not page-aligned. */
		if (!is_aligned(ipa_addr(begin), PAGE_SIZE) ||
		    !is_aligned(ipa_addr(end), PAGE_SIZE)) {
			return ffa_error(FFA_INVALID_PARAMETERS);
		}

		/*
		 * Ensure that this constituent memory range is all mapped with
		 * the same mode.
		 */
		if (!mm_vm_get_mode(&vm.vm->ptable, begin, end,
				    &current_mode)) {
			return ffa_error(FFA_DENIED);
		}

		/*
		 * Ensure that all constituents are mapped with the same mode.
		 */
		if (i == 0) {
			*orig_mode = current_mode;
		} else if (current_mode != *orig_mode) {
			return ffa_error(FFA_DENIED);
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
	ffa_memory_access_permissions_t permissions, uint32_t *orig_from_mode,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	const uint32_t required_from_mode =
		ffa_memory_permissions_to_mode(permissions);
	struct ffa_value ret;

	ret = constituents_get_mode(from, orig_from_mode, constituents,
				    constituent_count);
	if (ret.func != FFA_SUCCESS_32) {
		return ret;
	}

	/* Ensure the address range is normal memory and not a device. */
	if (*orig_from_mode & MM_MODE_D) {
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

	if ((*orig_from_mode & required_from_mode) != required_from_mode) {
		dlog_verbose(
			"Sender tried to send memory with permissions which "
			"required mode %#x but only had %#x itself.\n",
			required_from_mode, *orig_from_mode);
		return ffa_error(FFA_DENIED);
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
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	uint32_t orig_from_state;
	struct ffa_value ret;

	ret = constituents_get_mode(from, orig_from_mode, constituents,
				    constituent_count);
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
			"but "
			"should be %#x).\n",
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
static struct ffa_value ffa_retrieve_check_transition(
	struct vm_locked to, uint32_t share_func,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes,
	uint32_t *to_mode)
{
	uint32_t orig_to_mode;
	struct ffa_value ret;

	ret = constituents_get_mode(to, &orig_to_mode, constituents,
				    constituent_count);
	if (ret.func != FFA_SUCCESS_32) {
		return ret;
	}

	if (share_func == FFA_MEM_RECLAIM_32) {
		const uint32_t state_mask =
			MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
		uint32_t orig_to_state = orig_to_mode & state_mask;

		if (orig_to_state != MM_MODE_INVALID &&
		    orig_to_state != MM_MODE_SHARED) {
			return ffa_error(FFA_DENIED);
		}
	} else {
		/*
		 * Ensure the retriever has the expected state. We don't care
		 * about the MM_MODE_SHARED bit; either with or without it set
		 * are both valid representations of the !O-NA state.
		 */
		if ((orig_to_mode & MM_MODE_UNMAPPED_MASK) !=
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
 * mm_vm_defrag should always be called after a series of page table updates,
 * whether they succeed or fail.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made to memory mappings.
 */
static bool ffa_region_group_identity_map(
	struct vm_locked vm_locked,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, int mode, struct mpool *ppool, bool commit)
{
	/* Iterate over the memory region constituents. */
	for (uint32_t index = 0; index < constituent_count; index++) {
		size_t size = constituents[index].page_count * PAGE_SIZE;
		paddr_t pa_begin =
			pa_from_ipa(ipa_init(constituents[index].address));
		paddr_t pa_end = pa_add(pa_begin, size);

		if (commit) {
			vm_identity_commit(vm_locked, pa_begin, pa_end, mode,
					   ppool, NULL);
		} else if (!vm_identity_prepare(vm_locked, pa_begin, pa_end,
						mode, ppool)) {
			return false;
		}
	}

	return true;
}

/**
 * Clears a region of physical memory by overwriting it with zeros. The data is
 * flushed from the cache so the memory has been cleared across the system.
 */
static bool clear_memory(paddr_t begin, paddr_t end, struct mpool *ppool)
{
	/*
	 * TODO: change this to a CPU local single page window rather than a
	 *       global mapping of the whole range. Such an approach will limit
	 *       the changes to stage-1 tables and will allow only local
	 *       invalidation.
	 */
	bool ret;
	struct mm_stage1_locked stage1_locked = mm_lock_stage1();
	void *ptr =
		mm_identity_map(stage1_locked, begin, end, MM_MODE_W, ppool);
	size_t size = pa_difference(begin, end);

	if (!ptr) {
		/* TODO: partial defrag of failed range. */
		/* Recover any memory consumed in failed mapping. */
		mm_defrag(stage1_locked, ppool);
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
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, struct mpool *page_pool)
{
	struct mpool local_page_pool;
	struct mm_stage1_locked stage1_locked;
	bool ret = false;

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure each constituent that is mapped can be
	 * unmapped again afterwards.
	 */
	mpool_init_with_fallback(&local_page_pool, page_pool);

	/* Iterate over the memory region constituents. */
	for (uint32_t i = 0; i < constituent_count; ++i) {
		size_t size = constituents[i].page_count * PAGE_SIZE;
		paddr_t begin = pa_from_ipa(ipa_init(constituents[i].address));
		paddr_t end = pa_add(begin, size);

		if (!clear_memory(begin, end, &local_page_pool)) {
			/*
			 * api_clear_memory will defrag on failure, so no need
			 * to do it here.
			 */
			goto out;
		}
	}

	/*
	 * Need to defrag after clearing, as it may have added extra mappings to
	 * the stage 1 page table.
	 */
	stage1_locked = mm_lock_stage1();
	mm_defrag(stage1_locked, &local_page_pool);
	mm_unlock_stage1(&stage1_locked);

	ret = true;

out:
	mpool_fini(&local_page_pool);
	return ret;
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
 *   2) FFA_NO_MEMORY - Hafnium did not have sufficient memory to complete
 *     the request.
 *   3) FFA_DENIED - The sender doesn't have sufficient access to send the
 *     memory with the given permissions.
 *  Success is indicated by FFA_SUCCESS.
 */
static struct ffa_value ffa_send_memory(
	struct vm_locked from_locked,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t share_func,
	ffa_memory_access_permissions_t permissions, struct mpool *page_pool,
	bool clear)
{
	struct vm *from = from_locked.vm;
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	if (!is_aligned(constituents, 8)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the sender, ensure that
	 * all constituents of a memory region being shared are at the same
	 * state.
	 */
	ret = ffa_send_check_transition(from_locked, share_func, permissions,
					&orig_from_mode, constituents,
					constituent_count, &from_mode);
	if (ret.func != FFA_SUCCESS_32) {
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
	if (!ffa_region_group_identity_map(from_locked, constituents,
					   constituent_count, from_mode,
					   page_pool, false)) {
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
	CHECK(ffa_region_group_identity_map(from_locked, constituents,
					    constituent_count, from_mode,
					    &local_page_pool, true));

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !ffa_clear_memory_constituents(
			     constituents, constituent_count, page_pool)) {
		/*
		 * On failure, roll back by returning memory to the sender. This
		 * may allocate pages which were previously freed into
		 * `local_page_pool` by the call above, but will never allocate
		 * more pages than that so can never fail.
		 */
		CHECK(ffa_region_group_identity_map(
			from_locked, constituents, constituent_count,
			orig_from_mode, &local_page_pool, true));

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
	mm_vm_defrag(&from->ptable, page_pool);

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
static struct ffa_value ffa_retrieve_memory(
	struct vm_locked to_locked,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes,
	uint32_t share_func, bool clear, struct mpool *page_pool)
{
	struct vm *to = to_locked.vm;
	uint32_t to_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;

	/*
	 * Make sure constituents are properly aligned to a 32-bit boundary. If
	 * not we would get alignment faults trying to read (32-bit) values.
	 */
	if (!is_aligned(constituents, 4)) {
		dlog_verbose("Constituents not aligned.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the recipient, and ensure
	 * that all constituents of the memory region being retrieved are at the
	 * same state.
	 */
	ret = ffa_retrieve_check_transition(to_locked, share_func, constituents,
					    constituent_count,
					    memory_to_attributes, &to_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition.\n");
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
	if (!ffa_region_group_identity_map(to_locked, constituents,
					   constituent_count, to_mode,
					   page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		dlog_verbose(
			"Insufficient memory to update recipient page "
			"table.\n");
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !ffa_clear_memory_constituents(
			     constituents, constituent_count, page_pool)) {
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/*
	 * Complete the transfer by mapping the memory into the recipient. This
	 * won't allocate because the transaction was already prepared above, so
	 * it doesn't need to use the `local_page_pool`.
	 */
	CHECK(ffa_region_group_identity_map(to_locked, constituents,
					    constituent_count, to_mode,
					    page_pool, true));

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was
	 * an error) or merging entries into blocks where possible (on success).
	 */
	mm_vm_defrag(&to->ptable, page_pool);

	return ret;
}

/**
 * Reclaims the given memory from the TEE. To do this space is first reserved in
 * the <to> VM's page table, then the reclaim request is sent on to the TEE,
 * then (if that is successful) the memory is mapped back into the <to> VM's
 * page table.
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
static struct ffa_value ffa_tee_reclaim_memory(
	struct vm_locked to_locked, ffa_memory_handle_t handle,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes, bool clear,
	struct mpool *page_pool)
{
	struct vm *to = to_locked.vm;
	uint32_t to_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;
	ffa_memory_region_flags_t tee_flags;

	/*
	 * Make sure constituents are properly aligned to a 32-bit boundary. If
	 * not we would get alignment faults trying to read (32-bit) values.
	 */
	if (!is_aligned(constituents, 4)) {
		dlog_verbose("Constituents not aligned.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the recipient, and ensure
	 * that all constituents of the memory region being retrieved are at the
	 * same state.
	 */
	ret = ffa_retrieve_check_transition(to_locked, FFA_MEM_RECLAIM_32,
					    constituents, constituent_count,
					    memory_to_attributes, &to_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition.\n");
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
	if (!ffa_region_group_identity_map(to_locked, constituents,
					   constituent_count, to_mode,
					   page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		dlog_verbose(
			"Insufficient memory to update recipient page "
			"table.\n");
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	/*
	 * Forward the request to the TEE and see what happens.
	 */
	tee_flags = 0;
	if (clear) {
		tee_flags |= FFA_MEMORY_REGION_FLAG_CLEAR;
	}
	ret = arch_tee_call((struct ffa_value){.func = FFA_MEM_RECLAIM_32,
					       .arg1 = (uint32_t)handle,
					       .arg2 = (uint32_t)(handle >> 32),
					       .arg3 = tee_flags});

	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose(
			"Got %#x (%d) from EL3 in response to "
			"FFA_MEM_RECLAIM_32, expected FFA_SUCCESS_32.\n",
			ret.func, ret.arg2);
		goto out;
	}

	/*
	 * The TEE was happy with it, so complete the reclaim by mapping the
	 * memory into the recipient. This won't allocate because the
	 * transaction was already prepared above, so it doesn't need to use the
	 * `local_page_pool`.
	 */
	CHECK(ffa_region_group_identity_map(to_locked, constituents,
					    constituent_count, to_mode,
					    page_pool, true));

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was
	 * an error) or merging entries into blocks where possible (on success).
	 */
	mm_vm_defrag(&to->ptable, page_pool);

	return ret;
}

static struct ffa_value ffa_relinquish_memory(
	struct vm_locked from_locked,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, struct mpool *page_pool, bool clear)
{
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;

	ret = ffa_relinquish_check_transition(from_locked, &orig_from_mode,
					      constituents, constituent_count,
					      &from_mode);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Invalid transition.\n");
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
	if (!ffa_region_group_identity_map(from_locked, constituents,
					   constituent_count, from_mode,
					   page_pool, false)) {
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
	CHECK(ffa_region_group_identity_map(from_locked, constituents,
					    constituent_count, from_mode,
					    &local_page_pool, true));

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !ffa_clear_memory_constituents(
			     constituents, constituent_count, page_pool)) {
		/*
		 * On failure, roll back by returning memory to the sender. This
		 * may allocate pages which were previously freed into
		 * `local_page_pool` by the call above, but will never allocate
		 * more pages than that so can never fail.
		 */
		CHECK(ffa_region_group_identity_map(
			from_locked, constituents, constituent_count,
			orig_from_mode, &local_page_pool, true));

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
	mm_vm_defrag(&from_locked.vm->ptable, page_pool);

	return ret;
}

/**
 * Check that the given `memory_region` represents a valid memory send request
 * of the given `share_func` type, return the clear flag and permissions via the
 * respective output parameters, and update the permissions if necessary.
 * Returns FFA_SUCCESS if the request was valid, or the relevant FFA_ERROR if
 * not.
 */
static struct ffa_value ffa_memory_send_validate(
	struct vm *to, struct vm_locked from_locked,
	struct ffa_memory_region *memory_region, uint32_t memory_share_size,
	uint32_t share_func, bool *clear,
	ffa_memory_access_permissions_t *permissions)
{
	struct ffa_composite_memory_region *composite;
	uint32_t receivers_size;
	uint32_t constituents_size;
	enum ffa_data_access data_access;
	enum ffa_instruction_access instruction_access;

	CHECK(clear != NULL);
	CHECK(permissions != NULL);

	/* The sender must match the message sender. */
	if (memory_region->sender != from_locked.vm->id) {
		dlog_verbose("Invalid sender %d.\n", memory_region->sender);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* We only support a single recipient. */
	if (memory_region->receiver_count != 1) {
		dlog_verbose("Multiple recipients not supported.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Ensure that the composite header is within the memory bounds and
	 * doesn't overlap the first part of the message.
	 */
	receivers_size = sizeof(struct ffa_memory_access) *
			 memory_region->receiver_count;
	if (memory_region->receivers[0].composite_memory_region_offset <
		    sizeof(struct ffa_memory_region) + receivers_size ||
	    memory_region->receivers[0].composite_memory_region_offset +
			    sizeof(struct ffa_composite_memory_region) >=
		    memory_share_size) {
		dlog_verbose(
			"Invalid composite memory region descriptor offset.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);

	/*
	 * Ensure the number of constituents are within the memory
	 * bounds.
	 */
	constituents_size = sizeof(struct ffa_memory_region_constituent) *
			    composite->constituent_count;
	if (memory_share_size !=
	    memory_region->receivers[0].composite_memory_region_offset +
		    sizeof(struct ffa_composite_memory_region) +
		    constituents_size) {
		dlog_verbose("Invalid size %d or constituent offset %d.\n",
			     memory_share_size,
			     memory_region->receivers[0]
				     .composite_memory_region_offset);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* The recipient must match the message recipient. */
	if (memory_region->receivers[0].receiver_permissions.receiver !=
	    to->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	*clear = memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR;
	/*
	 * Clear is not allowed for memory sharing, as the sender still has
	 * access to the memory.
	 */
	if (*clear && share_func == FFA_MEM_SHARE_32) {
		dlog_verbose("Memory can't be cleared while being shared.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* No other flags are allowed/supported here. */
	if (memory_region->flags & ~FFA_MEMORY_REGION_FLAG_CLEAR) {
		dlog_verbose("Invalid flags %#x.\n", memory_region->flags);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Check that the permissions are valid. */
	*permissions =
		memory_region->receivers[0].receiver_permissions.permissions;
	data_access = ffa_get_data_access_attr(*permissions);
	instruction_access = ffa_get_instruction_access_attr(*permissions);
	if (data_access == FFA_DATA_ACCESS_RESERVED ||
	    instruction_access == FFA_INSTRUCTION_ACCESS_RESERVED) {
		dlog_verbose("Reserved value for receiver permissions %#x.\n",
			     *permissions);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if (instruction_access != FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED) {
		dlog_verbose(
			"Invalid instruction access permissions %#x for "
			"sending memory.\n",
			*permissions);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if (share_func == FFA_MEM_SHARE_32) {
		if (data_access == FFA_DATA_ACCESS_NOT_SPECIFIED) {
			dlog_verbose(
				"Invalid data access permissions %#x for "
				"sharing memory.\n",
				*permissions);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		/*
		 * According to section 6.11.3 of the FF-A spec NX is required
		 * for share operations (but must not be specified by the
		 * sender) so set it in the copy that we store, ready to be
		 * returned to the retriever.
		 */
		ffa_set_instruction_access_attr(permissions,
						FFA_INSTRUCTION_ACCESS_NX);
		memory_region->receivers[0].receiver_permissions.permissions =
			*permissions;
	}
	if (share_func == FFA_MEM_LEND_32 &&
	    data_access == FFA_DATA_ACCESS_NOT_SPECIFIED) {
		dlog_verbose(
			"Invalid data access permissions %#x for lending "
			"memory.\n",
			*permissions);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if (share_func == FFA_MEM_DONATE_32 &&
	    data_access != FFA_DATA_ACCESS_NOT_SPECIFIED) {
		dlog_verbose(
			"Invalid data access permissions %#x for donating "
			"memory.\n",
			*permissions);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Validates a call to donate, lend or share memory and then updates the stage-2
 * page tables. Specifically, check if the message length and number of memory
 * region constituents match, and if the transition is valid for the type of
 * memory sending operation.
 *
 * Assumes that the caller has already found and locked both VMs and ensured
 * that the destination RX buffer is available, and copied the memory region
 * descriptor from the sender's TX buffer to a freshly allocated page from
 * Hafnium's internal pool.
 *
 * This function takes ownership of the `memory_region` passed in; it must not
 * be freed by the caller.
 */
struct ffa_value ffa_memory_send(struct vm *to, struct vm_locked from_locked,
				 struct ffa_memory_region *memory_region,
				 uint32_t memory_share_size,
				 uint32_t share_func, struct mpool *page_pool)
{
	struct ffa_composite_memory_region *composite;
	bool clear;
	ffa_memory_access_permissions_t permissions;
	struct ffa_value ret;
	ffa_memory_handle_t handle;

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(to, from_locked, memory_region,
				       memory_share_size, share_func, &clear,
				       &permissions);
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

	/*
	 * Allocate a share state before updating the page table. Otherwise if
	 * updating the page table succeeded but allocating the share state
	 * failed then it would leave the memory in a state where nobody could
	 * get it back.
	 */
	if (to->id != HF_TEE_VM_ID &&
	    !allocate_share_state(share_func, memory_region, &handle)) {
		dlog_verbose("Failed to allocate share state.\n");
		mpool_free(page_pool, memory_region);
		return ffa_error(FFA_NO_MEMORY);
	}

	dump_share_states();

	/* Check that state is valid in sender page table and update. */
	composite = ffa_memory_region_get_composite(memory_region, 0);
	ret = ffa_send_memory(from_locked, composite->constituents,
			      composite->constituent_count, share_func,
			      permissions, page_pool, clear);
	if (ret.func != FFA_SUCCESS_32) {
		if (to->id != HF_TEE_VM_ID) {
			/* Free share state. */
			bool freed = share_state_free_handle(handle, page_pool);

			CHECK(freed);
		}

		return ret;
	}

	if (to->id == HF_TEE_VM_ID) {
		/* No share state allocated here so no handle to return. */
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	}

	return ffa_mem_success(handle);
}

struct ffa_value ffa_memory_retrieve(struct vm_locked to_locked,
				     struct ffa_memory_region *retrieve_request,
				     uint32_t retrieve_request_size,
				     struct mpool *page_pool)
{
	uint32_t expected_retrieve_request_size =
		sizeof(struct ffa_memory_region) +
		retrieve_request->receiver_count *
			sizeof(struct ffa_memory_access);
	ffa_memory_handle_t handle = retrieve_request->handle;
	ffa_memory_region_flags_t transaction_type =
		retrieve_request->flags &
		FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK;
	struct ffa_memory_region *memory_region;
	ffa_memory_access_permissions_t sent_permissions;
	enum ffa_data_access sent_data_access;
	enum ffa_instruction_access sent_instruction_access;
	ffa_memory_access_permissions_t requested_permissions;
	enum ffa_data_access requested_data_access;
	enum ffa_instruction_access requested_instruction_access;
	ffa_memory_access_permissions_t permissions;
	uint32_t memory_to_attributes;
	struct ffa_composite_memory_region *composite;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	uint32_t response_size;

	dump_share_states();

	if (retrieve_request_size != expected_retrieve_request_size) {
		dlog_verbose(
			"Invalid length for FFA_MEM_RETRIEVE_REQ, expected %d "
			"but was %d.\n",
			expected_retrieve_request_size, retrieve_request_size);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (retrieve_request->receiver_count != 1) {
		dlog_verbose(
			"Multi-way memory sharing not supported (got %d "
			"receivers descriptors on FFA_MEM_RETRIEVE_REQ, "
			"expected 1).\n",
			retrieve_request->receiver_count);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RETRIEVE_REQ.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	/*
	 * Check that the transaction type expected by the receiver is correct,
	 * if it has been specified.
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
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_request->sender != memory_region->sender) {
		dlog_verbose(
			"Incorrect sender ID %d for FFA_MEM_RETRIEVE_REQ, "
			"expected %d for handle %#x.\n",
			retrieve_request->sender, memory_region->sender,
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_request->tag != memory_region->tag) {
		dlog_verbose(
			"Incorrect tag %d for FFA_MEM_RETRIEVE_REQ, expected "
			"%d for handle %#x.\n",
			retrieve_request->tag, memory_region->tag, handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_request->receivers[0].receiver_permissions.receiver !=
	    to_locked.vm->id) {
		dlog_verbose(
			"Retrieve request receiver VM ID %d didn't match "
			"caller of FFA_MEM_RETRIEVE_REQ.\n",
			retrieve_request->receivers[0]
				.receiver_permissions.receiver);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->receivers[0].receiver_permissions.receiver !=
	    to_locked.vm->id) {
		dlog_verbose(
			"Incorrect receiver VM ID %d for "
			"FFA_MEM_RETRIEVE_REQ, expected %d for handle %#x.\n",
			to_locked.vm->id,
			memory_region->receivers[0]
				.receiver_permissions.receiver,
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (share_state->retrieved[0]) {
		dlog_verbose("Memory with handle %#x already retrieved.\n",
			     handle);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (retrieve_request->receivers[0].composite_memory_region_offset !=
	    0) {
		dlog_verbose(
			"Retriever specified address ranges not supported (got "
			"offset"
			"%d).\n",
			retrieve_request->receivers[0]
				.composite_memory_region_offset);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Check permissions from sender against permissions requested by
	 * receiver.
	 */
	/* TODO: Check attributes too. */
	sent_permissions =
		memory_region->receivers[0].receiver_permissions.permissions;
	sent_data_access = ffa_get_data_access_attr(sent_permissions);
	sent_instruction_access =
		ffa_get_instruction_access_attr(sent_permissions);
	requested_permissions =
		retrieve_request->receivers[0].receiver_permissions.permissions;
	requested_data_access = ffa_get_data_access_attr(requested_permissions);
	requested_instruction_access =
		ffa_get_instruction_access_attr(requested_permissions);
	permissions = 0;
	switch (sent_data_access) {
	case FFA_DATA_ACCESS_NOT_SPECIFIED:
	case FFA_DATA_ACCESS_RW:
		if (requested_data_access == FFA_DATA_ACCESS_NOT_SPECIFIED ||
		    requested_data_access == FFA_DATA_ACCESS_RW) {
			ffa_set_data_access_attr(&permissions,
						 FFA_DATA_ACCESS_RW);
			break;
		}
		/* Intentional fall-through. */
	case FFA_DATA_ACCESS_RO:
		if (requested_data_access == FFA_DATA_ACCESS_NOT_SPECIFIED ||
		    requested_data_access == FFA_DATA_ACCESS_RO) {
			ffa_set_data_access_attr(&permissions,
						 FFA_DATA_ACCESS_RO);
			break;
		}
		dlog_verbose(
			"Invalid data access requested; sender specified "
			"permissions %#x but receiver requested %#x.\n",
			sent_permissions, requested_permissions);
		ret = ffa_error(FFA_DENIED);
		goto out;
	case FFA_DATA_ACCESS_RESERVED:
		panic("Got unexpected FFA_DATA_ACCESS_RESERVED. Should be "
		      "checked before this point.");
	}
	switch (sent_instruction_access) {
	case FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED:
	case FFA_INSTRUCTION_ACCESS_X:
		if (requested_instruction_access ==
			    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED ||
		    requested_instruction_access == FFA_INSTRUCTION_ACCESS_X) {
			ffa_set_instruction_access_attr(
				&permissions, FFA_INSTRUCTION_ACCESS_X);
			break;
		}
	case FFA_INSTRUCTION_ACCESS_NX:
		if (requested_instruction_access ==
			    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED ||
		    requested_instruction_access == FFA_INSTRUCTION_ACCESS_NX) {
			ffa_set_instruction_access_attr(
				&permissions, FFA_INSTRUCTION_ACCESS_NX);
			break;
		}
		dlog_verbose(
			"Invalid instruction access requested; sender "
			"specified "
			"permissions %#x but receiver requested %#x.\n",
			sent_permissions, requested_permissions);
		ret = ffa_error(FFA_DENIED);
		goto out;
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		panic("Got unexpected FFA_INSTRUCTION_ACCESS_RESERVED. Should "
		      "be checked before this point.");
	}
	memory_to_attributes = ffa_memory_permissions_to_mode(permissions);

	composite = ffa_memory_region_get_composite(memory_region, 0);
	ret = ffa_retrieve_memory(to_locked, composite->constituents,
				  composite->constituent_count,
				  memory_to_attributes, share_state->share_func,
				  false, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out;
	}

	/*
	 * Copy response to RX buffer of caller and deliver the message. This
	 * must be done before the share_state is (possibly) freed.
	 */
	/* TODO: combine attributes from sender and request. */
	response_size = ffa_retrieved_memory_region_init(
		to_locked.vm->mailbox.recv, HF_MAILBOX_SIZE,
		memory_region->sender, memory_region->attributes,
		memory_region->flags, handle, to_locked.vm->id, permissions,
		composite->constituents, composite->constituent_count);
	to_locked.vm->mailbox.recv_size = response_size;
	to_locked.vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	to_locked.vm->mailbox.recv_func = FFA_MEM_RETRIEVE_RESP_32;
	to_locked.vm->mailbox.state = MAILBOX_STATE_READ;

	if (share_state->share_func == FFA_MEM_DONATE_32) {
		/*
		 * Memory that has been donated can't be relinquished, so no
		 * need to keep the share state around.
		 */
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state for donate.\n");
	} else {
		share_state->retrieved[0] = true;
	}

	ret = (struct ffa_value){.func = FFA_MEM_RETRIEVE_RESP_32,
				 .arg1 = response_size,
				 .arg2 = response_size};

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
	struct ffa_composite_memory_region *composite;
	struct ffa_value ret;

	if (relinquish_request->endpoint_count != 1) {
		dlog_verbose(
			"Stream endpoints not supported (got %d endpoints on "
			"FFA_MEM_RELINQUISH, expected 1).\n",
			relinquish_request->endpoint_count);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (relinquish_request->endpoints[0] != from_locked.vm->id) {
		dlog_verbose(
			"VM ID %d in relinquish message doesn't match calling "
			"VM ID %d.\n",
			relinquish_request->endpoints[0], from_locked.vm->id);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	dump_share_states();

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RELINQUISH.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (memory_region->receivers[0].receiver_permissions.receiver !=
	    from_locked.vm->id) {
		dlog_verbose(
			"VM ID %d tried to relinquish memory region with "
			"handle %#x but receiver was %d.\n",
			from_locked.vm->id, handle,
			memory_region->receivers[0]
				.receiver_permissions.receiver);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->retrieved[0]) {
		dlog_verbose(
			"Memory with handle %#x not yet retrieved, can't "
			"relinquish.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	clear = relinquish_request->flags & FFA_MEMORY_REGION_FLAG_CLEAR;

	/*
	 * Clear is not allowed for memory that was shared, as the original
	 * sender still has access to the memory.
	 */
	if (clear && share_state->share_func == FFA_MEM_SHARE_32) {
		dlog_verbose("Memory which was shared can't be cleared.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);
	ret = ffa_relinquish_memory(from_locked, composite->constituents,
				    composite->constituent_count, page_pool,
				    clear);

	if (ret.func == FFA_SUCCESS_32) {
		/*
		 * Mark memory handle as not retrieved, so it can be reclaimed
		 * (or retrieved again).
		 */
		share_state->retrieved[0] = false;
	}

out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

/**
 * Validates that the reclaim transition is allowed for the given handle,
 * updates the page table of the reclaiming VM, and frees the internal state
 * associated with the handle.
 */
struct ffa_value ffa_memory_reclaim(struct vm_locked to_locked,
				    ffa_memory_handle_t handle, bool clear,
				    struct mpool *page_pool)
{
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint32_t memory_to_attributes = MM_MODE_R | MM_MODE_W | MM_MODE_X;
	struct ffa_value ret;

	dump_share_states();

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_RECLAIM.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %d attempted to reclaim memory handle %#x "
			"originally sent by VM %d.\n",
			to_locked.vm->id, handle, memory_region->sender);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (share_state->retrieved[0]) {
		dlog_verbose(
			"Tried to reclaim memory handle %#x that has not been "
			"relinquished.\n",
			handle);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);
	ret = ffa_retrieve_memory(to_locked, composite->constituents,
				  composite->constituent_count,
				  memory_to_attributes, FFA_MEM_RECLAIM_32,
				  clear, page_pool);

	if (ret.func == FFA_SUCCESS_32) {
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state after successful reclaim.\n");
	}

out:
	share_states_unlock(&share_states);
	return ret;
}

/**
 * Validates that the reclaim transition is allowed for the given memory region
 * and updates the page table of the reclaiming VM.
 */
struct ffa_value ffa_memory_tee_reclaim(struct vm_locked to_locked,
					ffa_memory_handle_t handle,
					struct ffa_memory_region *memory_region,
					bool clear, struct mpool *page_pool)
{
	uint32_t memory_to_attributes = MM_MODE_R | MM_MODE_W | MM_MODE_X;
	struct ffa_composite_memory_region *composite;

	if (memory_region->receiver_count != 1) {
		/* Only one receiver supported by Hafnium for now. */
		dlog_verbose(
			"Multiple recipients not supported (got %d, expected "
			"1).\n",
			memory_region->receiver_count);
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	if (memory_region->handle != handle) {
		dlog_verbose(
			"Got memory region handle %#x from TEE but requested "
			"handle %#x.\n",
			memory_region->handle, handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* The original sender must match the caller. */
	if (to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %d attempted to reclaim memory handle %#x "
			"originally sent by VM %d.\n",
			to_locked.vm->id, handle, memory_region->sender);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);

	/*
	 * Forward the request to the TEE and then map the memory back into the
	 * caller's stage-2 page table.
	 */
	return ffa_tee_reclaim_memory(to_locked, handle,
				      composite->constituents,
				      composite->constituent_count,
				      memory_to_attributes, clear, page_pool);
}
