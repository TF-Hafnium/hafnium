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

#include "hf/spci_memory.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/mpool.h"
#include "hf/spci_internal.h"
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

static_assert(sizeof(struct spci_memory_region_constituent) % 16 == 0,
	      "struct spci_memory_region_constituent must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct spci_memory_region_attributes) % 16 == 0,
	      "struct spci_memory_region_attributes must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct spci_memory_region) % 16 == 0,
	      "struct spci_memory_region must be a multiple of 16 bytes long.");
static_assert(sizeof(struct spci_receiver_address_range) % 16 == 0,
	      "struct spci_receiver_address_range must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct spci_retrieved_memory_region) % 16 == 0,
	      "struct spci_retrieved_memory_region must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct spci_memory_retrieve_properties) % 16 == 0,
	      "struct spci_memory_retrieve_properties must be a multiple of 16 "
	      "bytes long.");
static_assert(sizeof(struct spci_memory_retrieve_request) % 16 == 0,
	      "struct spci_memory_retrieve_request must be a multiple of 16 "
	      "bytes long.");

struct spci_memory_share_state {
	/**
	 * The memory region being shared, or NULL if this share state is
	 * unallocated.
	 */
	struct spci_memory_region *memory_region;

	/**
	 * The SPCI function used for sharing the memory. Must be one of
	 * SPCI_MEM_DONATE_32, SPCI_MEM_LEND_32 or SPCI_MEM_SHARE_32 if the
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
	struct spci_memory_share_state *share_states;
};

/**
 * All access to members of a `struct spci_memory_share_state` must be guarded
 * by this lock.
 */
static struct spinlock share_states_lock_instance = SPINLOCK_INIT;
static struct spci_memory_share_state share_states[MAX_MEM_SHARES];

/**
 * Initialises the next available `struct spci_memory_share_state` and sets
 * `handle` to its handle. Returns true on succes or false if none are
 * available.
 */
static bool allocate_share_state(uint32_t share_func,
				 struct spci_memory_region *memory_region,
				 spci_memory_handle_t *handle)
{
	uint32_t i;

	CHECK(memory_region != NULL);

	sl_lock(&share_states_lock_instance);
	for (i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states[i].share_func == 0) {
			uint32_t j;
			struct spci_memory_share_state *allocated_state =
				&share_states[i];
			allocated_state->share_func = share_func;
			allocated_state->memory_region = memory_region;
			for (j = 0; j < MAX_MEM_SHARE_RECIPIENTS; ++j) {
				allocated_state->retrieved[j] = false;
			}
			*handle = i | SPCI_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
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
			    spci_memory_handle_t handle,
			    struct spci_memory_share_state **share_state_ret)
{
	struct spci_memory_share_state *share_state;
	uint32_t index = handle & ~SPCI_MEMORY_HANDLE_ALLOCATOR_MASK;

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
			     struct spci_memory_share_state *share_state,
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
static bool share_state_free_handle(spci_memory_handle_t handle,
				    struct mpool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct spci_memory_share_state *share_state;

	if (!get_share_state(share_states, handle, &share_state)) {
		share_states_unlock(&share_states);
		return false;
	}

	share_state_free(share_states, share_state, page_pool);
	share_states_unlock(&share_states);

	return true;
}

static void dump_memory_region(struct spci_memory_region *memory_region)
{
	uint32_t i;

	if (LOG_LEVEL < LOG_LEVEL_VERBOSE) {
		return;
	}

	dlog("from VM %d, tag %d, flags %#x, %d total pages in %d constituents "
	     "to %d recipients [",
	     memory_region->sender, memory_region->tag, memory_region->flags,
	     memory_region->page_count, memory_region->constituent_count,
	     memory_region->attribute_count);
	for (i = 0; i < memory_region->attribute_count; ++i) {
		if (i != 0) {
			dlog(", ");
		}
		dlog("VM %d: %#x", memory_region->attributes[i].receiver,
		     memory_region->attributes[i].memory_attributes);
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
			case SPCI_MEM_SHARE_32:
				dlog("SHARE");
				break;
			case SPCI_MEM_LEND_32:
				dlog("LEND");
				break;
			case SPCI_MEM_DONATE_32:
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
static inline uint32_t spci_memory_attrs_to_mode(uint16_t memory_attributes)
{
	uint32_t mode = 0;

	switch (spci_get_memory_access_attr(memory_attributes)) {
	case SPCI_MEMORY_RO_NX:
		mode = MM_MODE_R;
		break;
	case SPCI_MEMORY_RO_X:
		mode = MM_MODE_R | MM_MODE_X;
		break;
	case SPCI_MEMORY_RW_NX:
		mode = MM_MODE_R | MM_MODE_W;
		break;
	case SPCI_MEMORY_RW_X:
		mode = MM_MODE_R | MM_MODE_W | MM_MODE_X;
		break;
	}

	return mode;
}

/**
 * Get the current mode in the stage-2 page table of the given vm of all the
 * pages in the given constituents, if they all have the same mode, or return
 * false if not.
 */
static bool constituents_get_mode(
	struct vm_locked vm, uint32_t *orig_mode,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count)
{
	uint32_t i;

	if (constituent_count == 0) {
		/*
		 * Fail if there are no constituents. Otherwise we would get an
		 * uninitialised *orig_mode.
		 */
		return false;
	}

	for (i = 0; i < constituent_count; ++i) {
		ipaddr_t begin =
			ipa_init(spci_memory_region_constituent_get_address(
				&constituents[i]));
		size_t size = constituents[i].page_count * PAGE_SIZE;
		ipaddr_t end = ipa_add(begin, size);
		uint32_t current_mode;

		/* Fail if addresses are not page-aligned. */
		if (!is_aligned(ipa_addr(begin), PAGE_SIZE) ||
		    !is_aligned(ipa_addr(end), PAGE_SIZE)) {
			return false;
		}

		/*
		 * Ensure that this constituent memory range is all mapped with
		 * the same mode.
		 */
		if (!mm_vm_get_mode(&vm.vm->ptable, begin, end,
				    &current_mode)) {
			return false;
		}

		/*
		 * Ensure that all constituents are mapped with the same mode.
		 */
		if (i == 0) {
			*orig_mode = current_mode;
		} else if (current_mode != *orig_mode) {
			return false;
		}
	}

	return true;
}

/**
 * Verify that all pages have the same mode, that the starting mode
 * constitutes a valid state and obtain the next mode to apply
 * to the sending VM.
 *
 * Returns:
 *  The error code false indicates that:
 *   1) a state transition was not found;
 *   2) the pages being shared do not have the same mode within the <from> VM;
 *   3) The beginning and end IPAs are not page aligned;
 *   4) The requested share type was not handled.
 *  Success is indicated by true.
 *
 */
static bool spci_send_check_transition(
	struct vm_locked from, uint32_t share_func, uint32_t *orig_from_mode,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;

	if (!constituents_get_mode(from, orig_from_mode, constituents,
				   constituent_count)) {
		return false;
	}

	/* Ensure the address range is normal memory and not a device. */
	if (*orig_from_mode & MM_MODE_D) {
		dlog_verbose("Can't share device memory (mode is %#x).\n",
			     *orig_from_mode);
		return false;
	}

	/*
	 * Ensure the sender is the owner and has exclusive access to the
	 * memory.
	 */
	if ((*orig_from_mode & state_mask) != 0) {
		return false;
	}

	/* Find the appropriate new mode. */
	*from_mode = ~state_mask & *orig_from_mode;
	switch (share_func) {
	case SPCI_MEM_DONATE_32:
		*from_mode |= MM_MODE_INVALID | MM_MODE_UNOWNED;
		break;

	case SPCI_MEM_LEND_32:
		*from_mode |= MM_MODE_INVALID;
		break;

	case SPCI_MEM_SHARE_32:
		*from_mode |= MM_MODE_SHARED;
		break;

	default:
		return false;
	}

	return true;
}

static bool spci_relinquish_check_transition(
	struct vm_locked from, uint32_t *orig_from_mode,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	uint32_t orig_from_state;

	if (!constituents_get_mode(from, orig_from_mode, constituents,
				   constituent_count)) {
		return false;
	}

	/* Ensure the address range is normal memory and not a device. */
	if (*orig_from_mode & MM_MODE_D) {
		dlog_verbose("Can't relinquish device memory (mode is %#x).\n",
			     *orig_from_mode);
		return false;
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
		return false;
	}

	/* Find the appropriate new mode. */
	*from_mode = (~state_mask & *orig_from_mode) | MM_MODE_UNMAPPED_MASK;

	return true;
}

/**
 * Verify that all pages have the same mode, that the starting mode
 * constitutes a valid state and obtain the next mode to apply
 * to the retrieving VM.
 *
 * Returns:
 *  The error code false indicates that:
 *   1) a state transition was not found;
 *   2) the pages being shared do not have the same mode within the <to> VM;
 *   3) The beginning and end IPAs are not page aligned;
 *   4) The requested share type was not handled.
 *  Success is indicated by true.
 */
static bool spci_retrieve_check_transition(
	struct vm_locked to, uint32_t share_func,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes,
	uint32_t *to_mode)
{
	uint32_t orig_to_mode;

	if (!constituents_get_mode(to, &orig_to_mode, constituents,
				   constituent_count)) {
		return false;
	}

	if (share_func == SPCI_MEM_RECLAIM_32) {
		const uint32_t state_mask =
			MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
		uint32_t orig_to_state = orig_to_mode & state_mask;

		if (orig_to_state != MM_MODE_INVALID &&
		    orig_to_state != MM_MODE_SHARED) {
			return false;
		}
	} else {
		/*
		 * Ensure the retriever has the expected state. We don't care
		 * about the MM_MODE_SHARED bit; either with or without it set
		 * are both valid representations of the !O-NA state.
		 */
		if ((orig_to_mode & MM_MODE_UNMAPPED_MASK) !=
		    MM_MODE_UNMAPPED_MASK) {
			return false;
		}
	}

	/* Find the appropriate new mode. */
	*to_mode = memory_to_attributes;
	switch (share_func) {
	case SPCI_MEM_DONATE_32:
		*to_mode |= 0;
		break;

	case SPCI_MEM_LEND_32:
		*to_mode |= MM_MODE_UNOWNED;
		break;

	case SPCI_MEM_SHARE_32:
		*to_mode |= MM_MODE_UNOWNED | MM_MODE_SHARED;
		break;

	case SPCI_MEM_RECLAIM_32:
		*to_mode |= 0;
		break;

	default:
		return false;
	}

	return true;
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
static bool spci_region_group_identity_map(
	struct vm_locked vm_locked,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, int mode, struct mpool *ppool, bool commit)
{
	/* Iterate over the memory region constituents. */
	for (uint32_t index = 0; index < constituent_count; index++) {
		size_t size = constituents[index].page_count * PAGE_SIZE;
		paddr_t pa_begin = pa_from_ipa(
			ipa_init(spci_memory_region_constituent_get_address(
				&constituents[index])));
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
static bool spci_clear_memory_constituents(
	struct spci_memory_region_constituent *constituents,
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
		paddr_t begin = pa_from_ipa(
			ipa_init(spci_memory_region_constituent_get_address(
				&constituents[i])));
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
 *   1) SPCI_INVALID_PARAMETERS - The endpoint provided parameters were
 *     erroneous;
 *   2) SPCI_NO_MEMORY - Hafnium did not have sufficient memory to complete
 *     the request.
 *  Success is indicated by SPCI_SUCCESS.
 */
static struct spci_value spci_send_memory(
	struct vm_locked from_locked,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t share_func,
	struct mpool *page_pool, bool clear)
{
	struct vm *from = from_locked.vm;
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct spci_value ret;

	/*
	 * Make sure constituents are properly aligned to a 32-bit boundary. If
	 * not we would get alignment faults trying to read (32-bit) values.
	 */
	if (!is_aligned(constituents, 4)) {
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the sender, ensure that
	 * all constituents of a memory region being shared are at the same
	 * state.
	 */
	if (!spci_send_check_transition(from_locked, share_func,
					&orig_from_mode, constituents,
					constituent_count, &from_mode)) {
		return spci_error(SPCI_INVALID_PARAMETERS);
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
	if (!spci_region_group_identity_map(from_locked, constituents,
					    constituent_count, from_mode,
					    page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		ret = spci_error(SPCI_NO_MEMORY);
		goto out;
	}

	/*
	 * Update the mapping for the sender. This won't allocate because the
	 * transaction was already prepared above, but may free pages in the
	 * case that a whole block is being unmapped that was previously
	 * partially mapped.
	 */
	CHECK(spci_region_group_identity_map(from_locked, constituents,
					     constituent_count, from_mode,
					     &local_page_pool, true));

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !spci_clear_memory_constituents(
			     constituents, constituent_count, page_pool)) {
		/*
		 * On failure, roll back by returning memory to the sender. This
		 * may allocate pages which were previously freed into
		 * `local_page_pool` by the call above, but will never allocate
		 * more pages than that so can never fail.
		 */
		CHECK(spci_region_group_identity_map(
			from_locked, constituents, constituent_count,
			orig_from_mode, &local_page_pool, true));

		ret = spci_error(SPCI_NO_MEMORY);
		goto out;
	}

	ret = (struct spci_value){.func = SPCI_SUCCESS_32};

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
 *   1) SPCI_INVALID_PARAMETERS - The endpoint provided parameters were
 *     erroneous;
 *   2) SPCI_NO_MEMORY - Hafnium did not have sufficient memory to complete
 *     the request.
 *  Success is indicated by SPCI_SUCCESS.
 */
static struct spci_value spci_retrieve_memory(
	struct vm_locked to_locked,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes,
	uint32_t share_func, bool clear, struct mpool *page_pool)
{
	struct vm *to = to_locked.vm;
	uint32_t to_mode;
	struct mpool local_page_pool;
	struct spci_value ret;

	/*
	 * Make sure constituents are properly aligned to a 32-bit boundary. If
	 * not we would get alignment faults trying to read (32-bit) values.
	 */
	if (!is_aligned(constituents, 4)) {
		dlog_verbose("Constituents not aligned.\n");
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the recipient, and ensure
	 * that all constituents of the memory region being retrieved are at the
	 * same state.
	 */
	if (!spci_retrieve_check_transition(to_locked, share_func, constituents,
					    constituent_count,
					    memory_to_attributes, &to_mode)) {
		dlog_verbose("Invalid transition.\n");
		return spci_error(SPCI_INVALID_PARAMETERS);
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
	if (!spci_region_group_identity_map(to_locked, constituents,
					    constituent_count, to_mode,
					    page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		dlog_verbose(
			"Insufficient memory to update recipient page "
			"table.\n");
		ret = spci_error(SPCI_NO_MEMORY);
		goto out;
	}

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !spci_clear_memory_constituents(
			     constituents, constituent_count, page_pool)) {
		ret = spci_error(SPCI_NO_MEMORY);
		goto out;
	}

	/*
	 * Complete the transfer by mapping the memory into the recipient. This
	 * won't allocate because the transaction was already prepared above, so
	 * it doesn't need to use the `local_page_pool`.
	 */
	CHECK(spci_region_group_identity_map(to_locked, constituents,
					     constituent_count, to_mode,
					     page_pool, true));

	ret = (struct spci_value){.func = SPCI_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);

	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was
	 * an error) or merging entries into blocks where possible (on success).
	 */
	mm_vm_defrag(&to->ptable, page_pool);

	return ret;
}

static struct spci_value spci_relinquish_memory(
	struct vm_locked from_locked,
	struct spci_memory_region_constituent *constituents,
	uint32_t constituent_count, struct mpool *page_pool, bool clear)
{
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct spci_value ret;

	if (!spci_relinquish_check_transition(from_locked, &orig_from_mode,
					      constituents, constituent_count,
					      &from_mode)) {
		dlog_verbose("Invalid transition.\n");
		return spci_error(SPCI_INVALID_PARAMETERS);
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
	if (!spci_region_group_identity_map(from_locked, constituents,
					    constituent_count, from_mode,
					    page_pool, false)) {
		/* TODO: partial defrag of failed range. */
		ret = spci_error(SPCI_NO_MEMORY);
		goto out;
	}

	/*
	 * Update the mapping for the sender. This won't allocate because the
	 * transaction was already prepared above, but may free pages in the
	 * case that a whole block is being unmapped that was previously
	 * partially mapped.
	 */
	CHECK(spci_region_group_identity_map(from_locked, constituents,
					     constituent_count, from_mode,
					     &local_page_pool, true));

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !spci_clear_memory_constituents(
			     constituents, constituent_count, page_pool)) {
		/*
		 * On failure, roll back by returning memory to the sender. This
		 * may allocate pages which were previously freed into
		 * `local_page_pool` by the call above, but will never allocate
		 * more pages than that so can never fail.
		 */
		CHECK(spci_region_group_identity_map(
			from_locked, constituents, constituent_count,
			orig_from_mode, &local_page_pool, true));

		ret = spci_error(SPCI_NO_MEMORY);
		goto out;
	}

	ret = (struct spci_value){.func = SPCI_SUCCESS_32};

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
struct spci_value spci_memory_send(struct vm *to, struct vm_locked from_locked,
				   struct spci_memory_region *memory_region,
				   uint32_t memory_share_size,
				   uint32_t share_func, struct mpool *page_pool)
{
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);
	uint32_t constituent_count = memory_region->constituent_count;
	uint32_t attributes_size;
	uint32_t constituents_size;
	bool clear;
	struct spci_value ret;
	spci_memory_handle_t handle;

	/*
	 * Ensure the number of constituents are within the memory
	 * bounds.
	 */
	attributes_size = sizeof(struct spci_memory_region_attributes) *
			  memory_region->attribute_count;
	constituents_size = sizeof(struct spci_memory_region_constituent) *
			    constituent_count;
	if (memory_region->constituent_offset <
		    sizeof(struct spci_memory_region) + attributes_size ||
	    memory_share_size !=
		    memory_region->constituent_offset + constituents_size) {
		dlog_verbose("Invalid size %d or constituent offset %d.\n",
			     memory_share_size,
			     memory_region->constituent_offset);
		mpool_free(page_pool, memory_region);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/* The sender must match the message sender. */
	if (memory_region->sender != from_locked.vm->id) {
		dlog_verbose("Invalid sender %d.\n", memory_region->sender);
		mpool_free(page_pool, memory_region);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/* We only support a single recipient. */
	if (memory_region->attribute_count != 1) {
		dlog_verbose("Multiple recipients not supported.\n");
		mpool_free(page_pool, memory_region);
		return spci_error(SPCI_NOT_SUPPORTED);
	}

	/* The recipient must match the message recipient. */
	if (memory_region->attributes[0].receiver != to->id) {
		mpool_free(page_pool, memory_region);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	clear = memory_region->flags & SPCI_MEMORY_REGION_FLAG_CLEAR;
	/*
	 * Clear is not allowed for memory sharing, as the sender still has
	 * access to the memory.
	 */
	if (clear && share_func == SPCI_MEM_SHARE_32) {
		dlog_verbose("Memory can't be cleared while being shared.\n");
		return spci_error(SPCI_INVALID_PARAMETERS);
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
		return spci_error(SPCI_NO_MEMORY);
	}

	dump_share_states();

	/* Check that state is valid in sender page table and update. */
	ret = spci_send_memory(from_locked, constituents, constituent_count,
			       share_func, page_pool, clear);
	if (ret.func != SPCI_SUCCESS_32) {
		if (to->id != HF_TEE_VM_ID) {
			/* Free share state. */
			bool freed = share_state_free_handle(handle, page_pool);

			CHECK(freed);
		}

		return ret;
	}

	if (to->id == HF_TEE_VM_ID) {
		/* Return directly, no need to allocate share state. */
		return (struct spci_value){.func = SPCI_SUCCESS_32};
	}

	return (struct spci_value){.func = SPCI_SUCCESS_32, .arg2 = handle};
}

struct spci_value spci_memory_retrieve(
	struct vm_locked to_locked,
	struct spci_memory_retrieve_request *retrieve_request,
	uint32_t retrieve_request_size, struct mpool *page_pool)
{
	uint32_t expected_retrieve_request_size =
		sizeof(struct spci_memory_retrieve_request) +
		retrieve_request->retrieve_properties_count *
			sizeof(struct spci_memory_retrieve_properties);
	spci_memory_handle_t handle = retrieve_request->handle;
	struct spci_memory_region *memory_region;
	struct spci_memory_retrieve_properties *retrieve_properties;
	uint32_t memory_to_attributes;
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count;
	struct share_states_locked share_states;
	struct spci_memory_share_state *share_state;
	struct spci_value ret;
	uint32_t response_size;

	dump_share_states();

	if (retrieve_request_size != expected_retrieve_request_size) {
		dlog_verbose(
			"Invalid length for SPCI_MEM_RETRIEVE_REQ, expected %d "
			"but was %d.\n",
			expected_retrieve_request_size, retrieve_request_size);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for SPCI_MEM_RETRIEVE_REQ.\n",
			     handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_request->share_func != share_state->share_func) {
		dlog_verbose(
			"Incorrect transaction type %#x for "
			"SPCI_MEM_RETRIEVE_REQ, expected %#x for handle %#x.\n",
			retrieve_request->share_func, share_state->share_func,
			handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (retrieve_request->sender != memory_region->sender) {
		dlog_verbose(
			"Incorrect sender ID %d for SPCI_MEM_RETRIEVE_REQ, "
			"expected %d for handle %#x.\n",
			retrieve_request->sender, memory_region->sender,
			handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_request->tag != memory_region->tag) {
		dlog_verbose(
			"Incorrect tag %d for SPCI_MEM_RETRIEVE_REQ, expected "
			"%d for handle %#x.\n",
			retrieve_request->tag, memory_region->tag, handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->attributes[0].receiver != to_locked.vm->id) {
		dlog_verbose(
			"Incorrect receiver VM ID %d for "
			"SPCI_MEM_RETRIEVE_REQ, expected %d for handle %#x.\n",
			to_locked.vm->id, memory_region->attributes[0].receiver,
			handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (share_state->retrieved[0]) {
		dlog_verbose("Memory with handle %#x already retrieved.\n",
			     handle);
		ret = spci_error(SPCI_DENIED);
		goto out;
	}

	if (retrieve_request->attribute_count != 0) {
		dlog_verbose(
			"Multi-way memory sharing not supported (got %d "
			"attribute descriptors on SPCI_MEM_RETRIEVE_REQ, "
			"expected 0).\n",
			retrieve_request->attribute_count);
		ret = spci_error(SPCI_NOT_SUPPORTED);
		goto out;
	}

	if (retrieve_request->retrieve_properties_count != 1) {
		dlog_verbose(
			"Stream endpoints not supported (got %d retrieve "
			"properties descriptors on SPCI_MEM_RETRIEVE_REQ, "
			"expected 1).\n",
			retrieve_request->retrieve_properties_count);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	retrieve_properties =
		spci_memory_retrieve_request_first_retrieve_properties(
			retrieve_request);

	if (retrieve_properties->attributes.receiver != to_locked.vm->id) {
		dlog_verbose(
			"Retrieve properties receiver VM ID %d didn't match "
			"caller of SPCI_MEM_RETRIEVE_REQ.\n",
			retrieve_properties->attributes.receiver);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_properties->page_count != memory_region->page_count) {
		dlog_verbose(
			"Incorrect page count %d for "
			"SPCI_MEM_RETRIEVE_REQ, expected %d for handle %#x.\n",
			retrieve_properties->page_count,
			memory_region->page_count, handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (retrieve_properties->constituent_count != 0) {
		dlog_verbose(
			"Retriever specified address ranges not supported (got "
			"%d).\n",
			retrieve_properties->constituent_count);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	memory_to_attributes = spci_memory_attrs_to_mode(
		memory_region->attributes[0].memory_attributes);

	constituents = spci_memory_region_get_constituents(memory_region);
	constituent_count = memory_region->constituent_count;
	ret = spci_retrieve_memory(to_locked, constituents, constituent_count,
				   memory_to_attributes,
				   share_state->share_func, false, page_pool);
	if (ret.func != SPCI_SUCCESS_32) {
		goto out;
	}

	/*
	 * Copy response to RX buffer of caller and deliver the message. This
	 * must be done before the share_state is (possibly) freed.
	 */
	response_size = spci_retrieved_memory_region_init(
		to_locked.vm->mailbox.recv, HF_MAILBOX_SIZE, to_locked.vm->id,
		constituents, constituent_count, memory_region->page_count);
	to_locked.vm->mailbox.recv_size = response_size;
	to_locked.vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	to_locked.vm->mailbox.recv_func = SPCI_MEM_RETRIEVE_RESP_32;
	to_locked.vm->mailbox.state = MAILBOX_STATE_READ;

	if (share_state->share_func == SPCI_MEM_DONATE_32) {
		/*
		 * Memory that has been donated can't be relinquished, so no
		 * need to keep the share state around.
		 */
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state for donate.\n");
	} else {
		share_state->retrieved[0] = true;
	}

	ret = (struct spci_value){.func = SPCI_MEM_RETRIEVE_RESP_32,
				  .arg3 = response_size,
				  .arg4 = response_size};

out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

struct spci_value spci_memory_relinquish(
	struct vm_locked from_locked,
	struct spci_mem_relinquish *relinquish_request, struct mpool *page_pool)
{
	spci_memory_handle_t handle = relinquish_request->handle;
	struct share_states_locked share_states;
	struct spci_memory_share_state *share_state;
	struct spci_memory_region *memory_region;
	bool clear;
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count;
	struct spci_value ret;

	if (relinquish_request->endpoint_count != 0) {
		dlog_verbose(
			"Stream endpoints not supported (got %d extra "
			"endpoints on SPCI_MEM_RELINQUISH, expected 0).\n",
			relinquish_request->endpoint_count);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	if (relinquish_request->sender != from_locked.vm->id) {
		dlog_verbose(
			"VM ID %d in relinquish message doesn't match calling "
			"VM ID %d.\n",
			relinquish_request->sender, from_locked.vm->id);
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	dump_share_states();

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for SPCI_MEM_RELINQUISH.\n",
			     handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (memory_region->attributes[0].receiver != from_locked.vm->id) {
		dlog_verbose(
			"VM ID %d tried to relinquish memory region with "
			"handle %#x but receiver was %d.\n",
			from_locked.vm->id, handle,
			memory_region->attributes[0].receiver);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->retrieved[0]) {
		dlog_verbose(
			"Memory with handle %#x not yet retrieved, can't "
			"relinquish.\n",
			handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	clear = relinquish_request->flags & SPCI_MEMORY_REGION_FLAG_CLEAR;

	/*
	 * Clear is not allowed for memory that was shared, as the original
	 * sender still has access to the memory.
	 */
	if (clear && share_state->share_func == SPCI_MEM_SHARE_32) {
		dlog_verbose("Memory which was shared can't be cleared.\n");
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	constituents = spci_memory_region_get_constituents(memory_region);
	constituent_count = memory_region->constituent_count;
	ret = spci_relinquish_memory(from_locked, constituents,
				     constituent_count, page_pool, clear);

	if (ret.func == SPCI_SUCCESS_32) {
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
struct spci_value spci_memory_reclaim(struct vm_locked to_locked,
				      spci_memory_handle_t handle, bool clear,
				      struct mpool *page_pool)
{
	struct share_states_locked share_states;
	struct spci_memory_share_state *share_state;
	struct spci_memory_region *memory_region;
	struct spci_memory_region_constituent *constituents;
	uint32_t constituent_count;
	uint32_t memory_to_attributes = MM_MODE_R | MM_MODE_W | MM_MODE_X;
	struct spci_value ret;

	dump_share_states();

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for SPCI_MEM_RECLAIM.\n",
			     handle);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %d attempted to reclaim memory handle %#x "
			"originally sent by VM %d.\n",
			to_locked.vm->id, handle, memory_region->sender);
		ret = spci_error(SPCI_INVALID_PARAMETERS);
		goto out;
	}

	if (share_state->retrieved[0]) {
		dlog_verbose(
			"Tried to reclaim memory handle %#x that has not been "
			"relinquished.\n",
			handle);
		ret = spci_error(SPCI_DENIED);
		goto out;
	}

	constituents = spci_memory_region_get_constituents(memory_region);
	constituent_count = memory_region->constituent_count;
	ret = spci_retrieve_memory(to_locked, constituents, constituent_count,
				   memory_to_attributes, SPCI_MEM_RECLAIM_32,
				   clear, page_pool);

	if (ret.func == SPCI_SUCCESS_32) {
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state after successful reclaim.\n");
	}

out:
	share_states_unlock(&share_states);
	return ret;
}
