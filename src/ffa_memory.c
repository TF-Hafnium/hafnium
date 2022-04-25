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

#include "hf/api.h"
#include "hf/assert.h"
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
 * Buffer for retrieving memory region information from the TEE for when a
 * region is reclaimed by a VM. Access to this buffer must be guarded by the VM
 * lock of the TEE VM.
 */
alignas(PAGE_SIZE) static uint8_t
	tee_retrieve_buffer[HF_MAILBOX_SIZE * MAX_FRAGMENTS];

/**
 * Extracts the index from a memory handle allocated by Hafnium's current world.
 */
uint64_t ffa_memory_handle_get_index(ffa_memory_handle_t handle)
{
	return handle & ~FFA_MEMORY_HANDLE_ALLOCATOR_MASK;
}

/**
 * Initialises the next available `struct ffa_memory_share_state` and sets
 * `share_state_ret` to a pointer to it. If `handle` is
 * `FFA_MEMORY_HANDLE_INVALID` then allocates an appropriate handle, otherwise
 * uses the provided handle which is assumed to be globally unique.
 *
 * Returns true on success or false if none are available.
 */
static bool allocate_share_state(
	struct share_states_locked share_states, uint32_t share_func,
	struct ffa_memory_region *memory_region, uint32_t fragment_length,
	ffa_memory_handle_t handle,
	struct ffa_memory_share_state **share_state_ret)
{
	uint64_t i;

	assert(share_states.share_states != NULL);
	assert(memory_region != NULL);

	for (i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states.share_states[i].share_func == 0) {
			uint32_t j;
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
			for (j = 0; j < MAX_MEM_SHARE_RECIPIENTS; ++j) {
				allocated_state->retrieved_fragment_count[j] =
					0;
			}
			if (share_state_ret != NULL) {
				*share_state_ret = allocated_state;
			}
			return true;
		}
	}

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
	assert(share_states->share_states != NULL);
	share_states->share_states = NULL;
	sl_unlock(&share_states_lock_instance);
}

/**
 * If the given handle is a valid handle for an allocated share state then
 * initialises `share_state_ret` to point to the share state and returns true.
 * Otherwise returns false.
 */
static bool get_share_state(struct share_states_locked share_states,
			    ffa_memory_handle_t handle,
			    struct ffa_memory_share_state **share_state_ret)
{
	struct ffa_memory_share_state *share_state;
	uint64_t index;

	assert(share_states.share_states != NULL);
	assert(share_state_ret != NULL);

	/*
	 * First look for a share_state allocated by us, in which case the
	 * handle is based on the index.
	 */
	if (plat_ffa_memory_handle_allocated_by_current_world(handle)) {
		index = ffa_memory_handle_get_index(handle);
		if (index < MAX_MEM_SHARES) {
			share_state = &share_states.share_states[index];
			if (share_state->share_func != 0) {
				*share_state_ret = share_state;
				return true;
			}
		}
	}

	/* Fall back to a linear scan. */
	for (index = 0; index < MAX_MEM_SHARES; ++index) {
		share_state = &share_states.share_states[index];
		if (share_state->memory_region != NULL &&
		    share_state->memory_region->handle == handle &&
		    share_state->share_func != 0) {
			*share_state_ret = share_state;
			return true;
		}
	}

	return false;
}

/** Marks a share state as unallocated. */
static void share_state_free(struct share_states_locked share_states,
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
}

/** Checks whether the given share state has been fully sent. */
static bool share_state_sending_complete(
	struct share_states_locked share_states,
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
static uint32_t share_state_next_fragment_offset(
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
				return ffa_error(FFA_INVALID_PARAMETERS);
			}

			/*
			 * Ensure that this constituent memory range is all
			 * mapped with the same mode.
			 */
			if (!vm_mem_get_mode(vm, begin, end, &current_mode)) {
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
					"Expected mode %#x but was %#x for %d "
					"pages at %#x.\n",
					*orig_mode, current_mode,
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
	ffa_memory_access_permissions_t permissions, uint32_t *orig_from_mode,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t *from_mode)
{
	const uint32_t state_mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	uint32_t required_from_mode;
	struct ffa_value ret;

	ret = constituents_get_mode(from, orig_from_mode, fragments,
				    fragment_constituent_counts,
				    fragment_count);
	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose("Inconsistent modes.\n");
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

	required_from_mode =
		ffa_memory_permissions_to_mode(permissions, *orig_from_mode);

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
static struct ffa_value ffa_retrieve_check_transition(
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
		assert((orig_to_mode & (MM_MODE_INVALID | MM_MODE_UNOWNED |
					MM_MODE_SHARED)) != 0U);
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
static bool ffa_region_group_identity_map(
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
			uint32_t pa_range = arch_mm_get_pa_range();

			/*
			 * Ensure the requested region falls into system's PA
			 * range.
			 */
			if (((pa_addr(pa_begin) >> pa_range) > 0) ||
			    ((pa_addr(pa_end) >> pa_range) > 0)) {
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
	uint32_t security_state_mode,
	struct ffa_memory_region_constituent **fragments,
	const uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	struct mpool *page_pool)
{
	struct mpool local_page_pool;
	uint32_t i;
	struct mm_stage1_locked stage1_locked;
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

		for (j = 0; j < fragment_constituent_counts[j]; ++j) {
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
 *   2) FFA_NO_MEMORY - Hafnium did not have sufficient memory to complete the
 *     request.
 *   3) FFA_DENIED - The sender doesn't have sufficient access to send the
 *     memory with the given permissions.
 *  Success is indicated by FFA_SUCCESS.
 */
static struct ffa_value ffa_send_check_update(
	struct vm_locked from_locked,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t share_func, ffa_memory_access_permissions_t permissions,
	struct mpool *page_pool, bool clear, uint32_t *orig_from_mode_ret)
{
	uint32_t i;
	uint32_t orig_from_mode;
	uint32_t from_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	for (i = 0; i < fragment_count; ++i) {
		if (!is_aligned(fragments[i], 8)) {
			dlog_verbose("Constituents not aligned.\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	}

	/*
	 * Check if the state transition is lawful for the sender, ensure that
	 * all constituents of a memory region being shared are at the same
	 * state.
	 */
	ret = ffa_send_check_transition(from_locked, share_func, permissions,
					&orig_from_mode, fragments,
					fragment_constituent_counts,
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
	    !ffa_clear_memory_constituents(
		    plat_ffa_owner_world_mode(from_locked.vm->id), fragments,
		    fragment_constituent_counts, fragment_count, page_pool)) {
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
static struct ffa_value ffa_retrieve_check_update(
	struct vm_locked to_locked, ffa_vm_id_t from_id,
	struct ffa_memory_region_constituent **fragments,
	uint32_t *fragment_constituent_counts, uint32_t fragment_count,
	uint32_t memory_to_attributes, uint32_t share_func, bool clear,
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
		fragment_count, memory_to_attributes, &to_mode);
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
	    !ffa_clear_memory_constituents(
		    plat_ffa_owner_world_mode(from_id), fragments,
		    fragment_constituent_counts, fragment_count, page_pool)) {
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
static struct ffa_value ffa_tee_reclaim_check_update(
	struct vm_locked to_locked, ffa_memory_handle_t handle,
	struct ffa_memory_region_constituent *constituents,
	uint32_t constituent_count, uint32_t memory_to_attributes, bool clear,
	struct mpool *page_pool)
{
	uint32_t to_mode;
	struct mpool local_page_pool;
	struct ffa_value ret;
	ffa_memory_region_flags_t tee_flags;

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	if (!is_aligned(constituents, 8)) {
		dlog_verbose("Constituents not aligned.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the state transition is lawful for the recipient, and ensure
	 * that all constituents of the memory region being retrieved are at the
	 * same state.
	 */
	ret = ffa_retrieve_check_transition(to_locked, FFA_MEM_RECLAIM_32,
					    &constituents, &constituent_count,
					    1, memory_to_attributes, &to_mode);
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
	if (!ffa_region_group_identity_map(to_locked, &constituents,
					   &constituent_count, 1, to_mode,
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
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_RECLAIM_32,
				   .arg1 = (uint32_t)handle,
				   .arg2 = (uint32_t)(handle >> 32),
				   .arg3 = tee_flags});

	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose(
			"Got %#x (%d) from TEE in response to FFA_MEM_RECLAIM, "
			"expected FFA_SUCCESS.\n",
			ret.func, ret.arg2);
		goto out;
	}

	/*
	 * The TEE was happy with it, so complete the reclaim by mapping the
	 * memory into the recipient. This won't allocate because the
	 * transaction was already prepared above, so it doesn't need to use the
	 * `local_page_pool`.
	 */
	CHECK(ffa_region_group_identity_map(to_locked, &constituents,
					    &constituent_count, 1, to_mode,
					    page_pool, true));

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
	    !ffa_clear_memory_constituents(
		    plat_ffa_owner_world_mode(from_locked.vm->id), fragments,
		    fragment_constituent_counts, fragment_count, page_pool)) {
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
static struct ffa_value ffa_memory_send_complete(
	struct vm_locked from_locked, struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state, struct mpool *page_pool,
	uint32_t *orig_from_mode_ret)
{
	struct ffa_memory_region *memory_region = share_state->memory_region;
	struct ffa_value ret;

	/* Lock must be held. */
	assert(share_states.share_states != NULL);

	/* Check that state is valid in sender page table and update. */
	ret = ffa_send_check_update(
		from_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, share_state->share_func,
		memory_region->receivers[0].receiver_permissions.permissions,
		page_pool, memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR,
		orig_from_mode_ret);
	if (ret.func != FFA_SUCCESS_32) {
		/*
		 * Free share state, it failed to send so it can't be retrieved.
		 */
		dlog_verbose("Complete failed, freeing share state.\n");
		share_state_free(share_states, share_state, page_pool);
		return ret;
	}

	share_state->sending_complete = true;
	dlog_verbose("Marked sending complete.\n");

	return ffa_mem_success(share_state->memory_region->handle);
}

/**
 * Check that the memory attributes match Hafnium expectations:
 * Normal Memory, Inner shareable, Write-Back Read-Allocate
 * Write-Allocate Cacheable.
 */
static struct ffa_value ffa_memory_attributes_validate(
	ffa_memory_access_permissions_t attributes)
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
static struct ffa_value ffa_memory_send_validate(
	struct vm_locked from_locked, struct ffa_memory_region *memory_region,
	uint32_t memory_share_length, uint32_t fragment_length,
	uint32_t share_func, ffa_memory_access_permissions_t *permissions)
{
	struct ffa_composite_memory_region *composite;
	uint32_t receivers_length;
	uint32_t composite_memory_region_offset;
	uint32_t constituents_offset;
	uint32_t constituents_length;
	enum ffa_data_access data_access;
	enum ffa_instruction_access instruction_access;
	struct ffa_value ret;

	assert(permissions != NULL);

	/*
	 * This should already be checked by the caller, just making the
	 * assumption clear here.
	 */
	assert(memory_region->receiver_count == 1);

	/* The sender must match the message sender. */
	if (memory_region->sender != from_locked.vm->id) {
		dlog_verbose("Invalid sender %d.\n", memory_region->sender);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Ensure that the composite header is within the memory bounds and
	 * doesn't overlap the first part of the message.
	 */
	receivers_length = sizeof(struct ffa_memory_access) *
			   memory_region->receiver_count;
	constituents_offset =
		ffa_composite_constituent_offset(memory_region, 0);
	composite_memory_region_offset =
		memory_region->receivers[0].composite_memory_region_offset;
	if ((composite_memory_region_offset == 0) ||
	    (composite_memory_region_offset <
	     sizeof(struct ffa_memory_region) + receivers_length) ||
	    constituents_offset > fragment_length) {
		dlog_verbose(
			"Invalid composite memory region descriptor offset "
			"%d.\n",
			memory_region->receivers[0]
				.composite_memory_region_offset);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);

	/*
	 * Ensure the number of constituents are within the memory bounds.
	 */
	constituents_length = sizeof(struct ffa_memory_region_constituent) *
			      composite->constituent_count;
	if (memory_share_length != constituents_offset + constituents_length) {
		dlog_verbose("Invalid length %d or composite offset %d.\n",
			     memory_share_length,
			     memory_region->receivers[0]
				     .composite_memory_region_offset);
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
		 * According to section 5.11.3 of the FF-A 1.0 spec NX is
		 * required for share operations (but must not be specified by
		 * the sender) so set it in the copy that we store, ready to be
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

	/*
	 * Check that sender's memory attributes match Hafnium expectations:
	 * Normal Memory, Inner shareable, Write-Back Read-Allocate
	 * Write-Allocate Cacheable.
	 */
	ret = ffa_memory_attributes_validate(memory_region->attributes);
	if (ret.func != FFA_SUCCESS_32) {
		return ret;
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/** Forwards a memory send message on to the TEE. */
static struct ffa_value memory_send_tee_forward(
	struct vm_locked tee_locked, ffa_vm_id_t sender_vm_id,
	uint32_t share_func, struct ffa_memory_region *memory_region,
	uint32_t memory_share_length, uint32_t fragment_length)
{
	struct ffa_value ret;

	memcpy_s(tee_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 memory_region, fragment_length);
	tee_locked.vm->mailbox.recv_size = fragment_length;
	tee_locked.vm->mailbox.recv_sender = sender_vm_id;
	tee_locked.vm->mailbox.recv_func = share_func;
	tee_locked.vm->mailbox.state = MAILBOX_STATE_RECEIVED;
	ret = arch_other_world_call(
		(struct ffa_value){.func = share_func,
				   .arg1 = memory_share_length,
				   .arg2 = fragment_length});
	/*
	 * After the call to the TEE completes it must have finished reading its
	 * RX buffer, so it is ready for another message.
	 */
	tee_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Gets the share state for continuing an operation to donate, lend or share
 * memory, and checks that it is a valid request.
 *
 * Returns FFA_SUCCESS if the request was valid, or the relevant FFA_ERROR if
 * not.
 */
static struct ffa_value ffa_memory_send_continue_validate(
	struct share_states_locked share_states, ffa_memory_handle_t handle,
	struct ffa_memory_share_state **share_state_ret, ffa_vm_id_t from_vm_id,
	struct mpool *page_pool)
{
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;

	assert(share_state_ret != NULL);

	/*
	 * Look up the share state by handle and make sure that the VM ID
	 * matches.
	 */
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose(
			"Invalid handle %#x for memory send continuation.\n",
			handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	memory_region = share_state->memory_region;

	if (memory_region->sender != from_vm_id) {
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
 * Forwards a memory send continuation message on to the TEE.
 */
static struct ffa_value memory_send_continue_tee_forward(
	struct vm_locked tee_locked, ffa_vm_id_t sender_vm_id, void *fragment,
	uint32_t fragment_length, ffa_memory_handle_t handle)
{
	struct ffa_value ret;

	memcpy_s(tee_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX, fragment,
		 fragment_length);
	tee_locked.vm->mailbox.recv_size = fragment_length;
	tee_locked.vm->mailbox.recv_sender = sender_vm_id;
	tee_locked.vm->mailbox.recv_func = FFA_MEM_FRAG_TX_32;
	tee_locked.vm->mailbox.state = MAILBOX_STATE_RECEIVED;
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_FRAG_TX_32,
				   .arg1 = (uint32_t)handle,
				   .arg2 = (uint32_t)(handle >> 32),
				   .arg3 = fragment_length,
				   .arg4 = (uint64_t)sender_vm_id << 16});
	/*
	 * After the call to the TEE completes it must have finished reading its
	 * RX buffer, so it is ready for another message.
	 */
	tee_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Validates a call to donate, lend or share memory to a non-TEE VM and then
 * updates the stage-2 page tables. Specifically, check if the message length
 * and number of memory region constituents match, and if the transition is
 * valid for the type of memory sending operation.
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
	ffa_memory_access_permissions_t permissions;
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
				       share_func, &permissions);
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
	if (!allocate_share_state(share_states, share_func, memory_region,
				  fragment_length, FFA_MEMORY_HANDLE_INVALID,
				  &share_state)) {
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
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)memory_region->handle,
			.arg2 = (uint32_t)(memory_region->handle >> 32),
			.arg3 = fragment_length};
	}

out:
	share_states_unlock(&share_states);
	dump_share_states();
	return ret;
}

/**
 * Validates a call to donate, lend or share memory to the TEE and then updates
 * the stage-2 page tables. Specifically, check if the message length and number
 * of memory region constituents match, and if the transition is valid for the
 * type of memory sending operation.
 *
 * Assumes that the caller has already found and locked the sender VM and the
 * TEE VM, and copied the memory region descriptor from the sender's TX buffer
 * to a freshly allocated page from Hafnium's internal pool. The caller must
 * have also validated that the receiver VM ID is valid.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
struct ffa_value ffa_memory_tee_send(
	struct vm_locked from_locked, struct vm_locked to_locked,
	struct ffa_memory_region *memory_region, uint32_t memory_share_length,
	uint32_t fragment_length, uint32_t share_func, struct mpool *page_pool)
{
	ffa_memory_access_permissions_t permissions;
	struct ffa_value ret;

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(from_locked, memory_region,
				       memory_share_length, fragment_length,
				       share_func, &permissions);
	if (ret.func != FFA_SUCCESS_32) {
		goto out;
	}

	if (fragment_length == memory_share_length) {
		/* No more fragments to come, everything fit in one message. */
		struct ffa_composite_memory_region *composite =
			ffa_memory_region_get_composite(memory_region, 0);
		struct ffa_memory_region_constituent *constituents =
			composite->constituents;
		struct mpool local_page_pool;
		uint32_t orig_from_mode;

		/*
		 * Use a local page pool so that we can roll back if necessary.
		 */
		mpool_init_with_fallback(&local_page_pool, page_pool);

		ret = ffa_send_check_update(
			from_locked, &constituents,
			&composite->constituent_count, 1, share_func,
			permissions, &local_page_pool,
			memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR,
			&orig_from_mode);
		if (ret.func != FFA_SUCCESS_32) {
			mpool_fini(&local_page_pool);
			goto out;
		}

		/* Forward memory send message on to TEE. */
		ret = memory_send_tee_forward(
			to_locked, from_locked.vm->id, share_func,
			memory_region, memory_share_length, fragment_length);

		if (ret.func != FFA_SUCCESS_32) {
			dlog_verbose(
				"TEE didn't successfully complete memory send "
				"operation; returned %#x (%d). Rolling back.\n",
				ret.func, ret.arg2);

			/*
			 * The TEE failed to complete the send operation, so
			 * roll back the page table update for the VM. This
			 * can't fail because it won't try to allocate more
			 * memory than was freed into the `local_page_pool` by
			 * `ffa_send_check_update` in the initial update.
			 */
			CHECK(ffa_region_group_identity_map(
				from_locked, &constituents,
				&composite->constituent_count, 1,
				orig_from_mode, &local_page_pool, true));
		}

		mpool_fini(&local_page_pool);
	} else {
		struct share_states_locked share_states = share_states_lock();
		ffa_memory_handle_t handle;

		/*
		 * We need to wait for the rest of the fragments before we can
		 * check whether the transaction is valid and unmap the memory.
		 * Call the TEE so it can do its initial validation and assign a
		 * handle, and allocate a share state to keep what we have so
		 * far.
		 */
		ret = memory_send_tee_forward(
			to_locked, from_locked.vm->id, share_func,
			memory_region, memory_share_length, fragment_length);
		if (ret.func == FFA_ERROR_32) {
			goto out_unlock;
		} else if (ret.func != FFA_MEM_FRAG_RX_32) {
			dlog_warning(
				"Got %#x from TEE in response to %#x for "
				"fragment with %d/%d, expected "
				"FFA_MEM_FRAG_RX.\n",
				ret.func, share_func, fragment_length,
				memory_share_length);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out_unlock;
		}
		handle = ffa_frag_handle(ret);
		if (ret.arg3 != fragment_length) {
			dlog_warning(
				"Got unexpected fragment offset %d for "
				"FFA_MEM_FRAG_RX from TEE (expected %d).\n",
				ret.arg3, fragment_length);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out_unlock;
		}
		if (ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_warning(
				"Got unexpected sender ID %d for "
				"FFA_MEM_FRAG_RX from TEE (expected %d).\n",
				ffa_frag_sender(ret), from_locked.vm->id);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out_unlock;
		}

		if (!allocate_share_state(share_states, share_func,
					  memory_region, fragment_length,
					  handle, NULL)) {
			dlog_verbose("Failed to allocate share state.\n");
			ret = ffa_error(FFA_NO_MEMORY);
			goto out_unlock;
		}
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	out_unlock:
		share_states_unlock(&share_states);
	}

out:
	if (memory_region != NULL) {
		mpool_free(page_pool, memory_region);
	}
	dump_share_states();
	return ret;
}

/**
 * Continues an operation to donate, lend or share memory to a non-TEE VM. If
 * this is the last fragment then checks that the transition is valid for the
 * type of memory sending operation and updates the stage-2 page tables of the
 * sender.
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

	ret = ffa_memory_send_continue_validate(share_states, handle,
						&share_state,
						from_locked.vm->id, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_free_fragment;
	}
	memory_region = share_state->memory_region;

	if (memory_region->receivers[0].receiver_permissions.receiver ==
	    HF_TEE_VM_ID) {
		dlog_error(
			"Got hypervisor-allocated handle for memory send to "
			"TEE. This should never happen, and indicates a bug in "
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

/**
 * Continues an operation to donate, lend or share memory to the TEE VM. If this
 * is the last fragment then checks that the transition is valid for the type of
 * memory sending operation and updates the stage-2 page tables of the sender.
 *
 * Assumes that the caller has already found and locked the sender VM and copied
 * the memory region descriptor from the sender's TX buffer to a freshly
 * allocated page from Hafnium's internal pool.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
struct ffa_value ffa_memory_tee_send_continue(struct vm_locked from_locked,
					      struct vm_locked to_locked,
					      void *fragment,
					      uint32_t fragment_length,
					      ffa_memory_handle_t handle,
					      struct mpool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;

	ret = ffa_memory_send_continue_validate(share_states, handle,
						&share_state,
						from_locked.vm->id, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_free_fragment;
	}
	memory_region = share_state->memory_region;

	if (memory_region->receivers[0].receiver_permissions.receiver !=
	    HF_TEE_VM_ID) {
		dlog_error(
			"Got SPM-allocated handle for memory send to non-TEE "
			"VM. This should never happen, and indicates a bug.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_free_fragment;
	}

	if (to_locked.vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	    to_locked.vm->mailbox.recv == NULL) {
		/*
		 * If the TEE RX buffer is not available, tell the sender to
		 * retry by returning the current offset again.
		 */
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)handle,
			.arg2 = (uint32_t)(handle >> 32),
			.arg3 = share_state_next_fragment_offset(share_states,
								 share_state),
		};
		goto out_free_fragment;
	}

	/* Add this fragment. */
	share_state->fragments[share_state->fragment_count] = fragment;
	share_state->fragment_constituent_counts[share_state->fragment_count] =
		fragment_length / sizeof(struct ffa_memory_region_constituent);
	share_state->fragment_count++;

	/* Check whether the memory send operation is now ready to complete. */
	if (share_state_sending_complete(share_states, share_state)) {
		struct mpool local_page_pool;
		uint32_t orig_from_mode;

		/*
		 * Use a local page pool so that we can roll back if necessary.
		 */
		mpool_init_with_fallback(&local_page_pool, page_pool);

		ret = ffa_memory_send_complete(from_locked, share_states,
					       share_state, &local_page_pool,
					       &orig_from_mode);

		if (ret.func == FFA_SUCCESS_32) {
			/*
			 * Forward final fragment on to the TEE so that
			 * it can complete the memory sending operation.
			 */
			ret = memory_send_continue_tee_forward(
				to_locked, from_locked.vm->id, fragment,
				fragment_length, handle);

			if (ret.func != FFA_SUCCESS_32) {
				/*
				 * The error will be passed on to the caller,
				 * but log it here too.
				 */
				dlog_verbose(
					"TEE didn't successfully complete "
					"memory send operation; returned %#x "
					"(%d). Rolling back.\n",
					ret.func, ret.arg2);

				/*
				 * The TEE failed to complete the send
				 * operation, so roll back the page table update
				 * for the VM. This can't fail because it won't
				 * try to allocate more memory than was freed
				 * into the `local_page_pool` by
				 * `ffa_send_check_update` in the initial
				 * update.
				 */
				CHECK(ffa_region_group_identity_map(
					from_locked, share_state->fragments,
					share_state
						->fragment_constituent_counts,
					share_state->fragment_count,
					orig_from_mode, &local_page_pool,
					true));
			}

			/* Free share state. */
			share_state_free(share_states, share_state, page_pool);
		} else {
			/* Abort sending to TEE. */
			struct ffa_value tee_ret =
				arch_other_world_call((struct ffa_value){
					.func = FFA_MEM_RECLAIM_32,
					.arg1 = (uint32_t)handle,
					.arg2 = (uint32_t)(handle >> 32)});

			if (tee_ret.func != FFA_SUCCESS_32) {
				/*
				 * Nothing we can do if TEE doesn't abort
				 * properly, just log it.
				 */
				dlog_verbose(
					"TEE didn't successfully abort failed "
					"memory send operation; returned %#x "
					"(%d).\n",
					tee_ret.func, tee_ret.arg2);
			}
			/*
			 * We don't need to free the share state in this case
			 * because ffa_memory_send_complete does that already.
			 */
		}

		mpool_fini(&local_page_pool);
	} else {
		uint32_t next_fragment_offset =
			share_state_next_fragment_offset(share_states,
							 share_state);

		ret = memory_send_continue_tee_forward(
			to_locked, from_locked.vm->id, fragment,
			fragment_length, handle);

		if (ret.func != FFA_MEM_FRAG_RX_32 ||
		    ffa_frag_handle(ret) != handle ||
		    ret.arg3 != next_fragment_offset ||
		    ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_verbose(
				"Got unexpected result from forwarding "
				"FFA_MEM_FRAG_TX to TEE: %#x (handle %#x, "
				"offset %d, sender %d); expected "
				"FFA_MEM_FRAG_RX (handle %#x, offset %d, "
				"sender %d).\n",
				ret.func, ffa_frag_handle(ret), ret.arg3,
				ffa_frag_sender(ret), handle,
				next_fragment_offset, from_locked.vm->id);
			/* Free share state. */
			share_state_free(share_states, share_state, page_pool);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		ret = (struct ffa_value){.func = FFA_MEM_FRAG_RX_32,
					 .arg1 = (uint32_t)handle,
					 .arg2 = (uint32_t)(handle >> 32),
					 .arg3 = next_fragment_offset};
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
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_composite_memory_region *composite;
	uint32_t total_length;
	uint32_t fragment_length;

	dump_share_states();

	if (retrieve_request_length != expected_retrieve_request_length) {
		dlog_verbose(
			"Invalid length for FFA_MEM_RETRIEVE_REQ, expected %d "
			"but was %d.\n",
			expected_retrieve_request_length,
			retrieve_request_length);
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
			"Incorrect receiver VM ID %d for FFA_MEM_RETRIEVE_REQ, "
			"expected %d for handle %#x.\n",
			to_locked.vm->id,
			memory_region->receivers[0]
				.receiver_permissions.receiver,
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

	if (share_state->retrieved_fragment_count[0] != 0) {
		dlog_verbose("Memory with handle %#x already retrieved.\n",
			     handle);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (retrieve_request->receivers[0].composite_memory_region_offset !=
	    0) {
		dlog_verbose(
			"Retriever specified address ranges not supported (got "
			"offset %d).\n",
			retrieve_request->receivers[0]
				.composite_memory_region_offset);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if ((retrieve_request->flags &
	     FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_VALID) != 0) {
		dlog_verbose(
			"Retriever specified 'address range alignment hint'"
			" not supported.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}
	if ((retrieve_request->flags &
	     FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_MASK) != 0) {
		dlog_verbose(
			"Bits 8-5 must be zero in memory region's flags "
			"(address range alignment hint not supported).\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if ((retrieve_request->flags & ~0x7FF) != 0U) {
		dlog_verbose(
			"Bits 31-10 must be zero in memory region's flags.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (share_state->share_func == FFA_MEM_SHARE_32 &&
	    (retrieve_request->flags &
	     (FFA_MEMORY_REGION_FLAG_CLEAR |
	      FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH)) != 0U) {
		dlog_verbose(
			"Memory Share operation can't clean after relinquish "
			"memory region.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * If the borrower needs the memory to be cleared before mapping to its
	 * address space, the sender should have set the flag when calling
	 * FFA_MEM_LEND/FFA_MEM_DONATE, else return FFA_DENIED.
	 */
	if ((retrieve_request->flags & FFA_MEMORY_REGION_FLAG_CLEAR) != 0U &&
	    (share_state->memory_region->flags &
	     FFA_MEMORY_REGION_FLAG_CLEAR) == 0U) {
		dlog_verbose(
			"Borrower needs memory cleared. Sender needs to set "
			"flag for clearing memory.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/*
	 * Check permissions from sender against permissions requested by
	 * receiver.
	 */
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

	if ((sent_data_access == FFA_DATA_ACCESS_RO ||
	     requested_permissions == FFA_DATA_ACCESS_RO) &&
	    (retrieve_request->flags & FFA_MEMORY_REGION_FLAG_CLEAR) != 0U) {
		dlog_verbose(
			"Receiver has RO permissions can not request clear.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

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
			"specified permissions %#x but receiver requested "
			"%#x.\n",
			sent_permissions, requested_permissions);
		ret = ffa_error(FFA_DENIED);
		goto out;
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		panic("Got unexpected FFA_INSTRUCTION_ACCESS_RESERVED. Should "
		      "be checked before this point.");
	}

	/*
	 * Ensure receiver's attributes are compatible with how Hafnium maps
	 * memory: Normal Memory, Inner shareable, Write-Back Read-Allocate
	 * Write-Allocate Cacheable.
	 */
	ret = ffa_memory_attributes_validate(retrieve_request->attributes);
	if (ret.func != FFA_SUCCESS_32) {
		goto out;
	}

	memory_to_attributes = ffa_memory_permissions_to_mode(
		permissions, share_state->sender_orig_mode);
	ret = ffa_retrieve_check_update(
		to_locked, memory_region->sender, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, memory_to_attributes,
		share_state->share_func, false, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out;
	}

	/*
	 * Copy response to RX buffer of caller and deliver the message. This
	 * must be done before the share_state is (possibly) freed.
	 */
	/* TODO: combine attributes from sender and request. */
	composite = ffa_memory_region_get_composite(memory_region, 0);
	/*
	 * Constituents which we received in the first fragment should always
	 * fit in the first fragment we are sending, because the header is the
	 * same size in both cases and we have a fixed message buffer size. So
	 * `ffa_retrieved_memory_region_init` should never fail.
	 */
	CHECK(ffa_retrieved_memory_region_init(
		to_locked.vm->mailbox.recv, HF_MAILBOX_SIZE,
		memory_region->sender, memory_region->attributes,
		memory_region->flags, handle, to_locked.vm->id, permissions,
		composite->page_count, composite->constituent_count,
		share_state->fragments[0],
		share_state->fragment_constituent_counts[0], &total_length,
		&fragment_length));
	to_locked.vm->mailbox.recv_size = fragment_length;
	to_locked.vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	to_locked.vm->mailbox.recv_func = FFA_MEM_RETRIEVE_RESP_32;
	to_locked.vm->mailbox.state = MAILBOX_STATE_READ;

	share_state->retrieved_fragment_count[0] = 1;
	if (share_state->retrieved_fragment_count[0] ==
	    share_state->fragment_count) {
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

struct ffa_value ffa_memory_retrieve_continue(struct vm_locked to_locked,
					      ffa_memory_handle_t handle,
					      uint32_t fragment_offset,
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

	dump_share_states();

	share_states = share_states_lock();
	if (!get_share_state(share_states, handle, &share_state)) {
		dlog_verbose("Invalid handle %#x for FFA_MEM_FRAG_RX.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	memory_region = share_state->memory_region;
	CHECK(memory_region != NULL);

	if (memory_region->receivers[0].receiver_permissions.receiver !=
	    to_locked.vm->id) {
		dlog_verbose(
			"Caller of FFA_MEM_FRAG_RX (%d) is not receiver (%d) "
			"of handle %#x.\n",
			to_locked.vm->id,
			memory_region->receivers[0]
				.receiver_permissions.receiver,
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

	if (share_state->retrieved_fragment_count[0] == 0 ||
	    share_state->retrieved_fragment_count[0] >=
		    share_state->fragment_count) {
		dlog_verbose(
			"Retrieval of memory with handle %#x not yet started "
			"or already completed (%d/%d fragments retrieved).\n",
			handle, share_state->retrieved_fragment_count[0],
			share_state->fragment_count);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	fragment_index = share_state->retrieved_fragment_count[0];

	/*
	 * Check that the given fragment offset is correct by counting how many
	 * constituents were in the fragments previously sent.
	 */
	retrieved_constituents_count = 0;
	for (i = 0; i < fragment_index; ++i) {
		retrieved_constituents_count +=
			share_state->fragment_constituent_counts[i];
	}
	expected_fragment_offset =
		ffa_composite_constituent_offset(memory_region, 0) +
		retrieved_constituents_count *
			sizeof(struct ffa_memory_region_constituent);
	if (fragment_offset != expected_fragment_offset) {
		dlog_verbose("Fragment offset was %d but expected %d.\n",
			     fragment_offset, expected_fragment_offset);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	remaining_constituent_count = ffa_memory_fragment_init(
		to_locked.vm->mailbox.recv, HF_MAILBOX_SIZE,
		share_state->fragments[fragment_index],
		share_state->fragment_constituent_counts[fragment_index],
		&fragment_length);
	CHECK(remaining_constituent_count == 0);
	to_locked.vm->mailbox.recv_size = fragment_length;
	to_locked.vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	to_locked.vm->mailbox.recv_func = FFA_MEM_FRAG_TX_32;
	to_locked.vm->mailbox.state = MAILBOX_STATE_READ;
	share_state->retrieved_fragment_count[0]++;
	if (share_state->retrieved_fragment_count[0] ==
	    share_state->fragment_count) {
		ffa_memory_retrieve_complete(share_states, share_state,
					     page_pool);
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

	if (share_state->retrieved_fragment_count[0] !=
	    share_state->fragment_count) {
		dlog_verbose(
			"Memory with handle %#x not yet fully retrieved, can't "
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

	ret = ffa_relinquish_check_update(
		from_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, page_pool, clear);

	if (ret.func == FFA_SUCCESS_32) {
		/*
		 * Mark memory handle as not retrieved, so it can be reclaimed
		 * (or retrieved again).
		 */
		share_state->retrieved_fragment_count[0] = 0;
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

	if (share_state->retrieved_fragment_count[0] != 0) {
		dlog_verbose(
			"Tried to reclaim memory handle %#x that has not been "
			"relinquished.\n",
			handle);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	ret = ffa_retrieve_check_update(
		to_locked, memory_region->sender, share_state->fragments,
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

/**
 * Validates that the reclaim transition is allowed for the memory region with
 * the given handle which was previously shared with the TEE, tells the TEE to
 * mark it as reclaimed, and updates the page table of the reclaiming VM.
 *
 * To do this information about the memory region is first fetched from the TEE.
 */
struct ffa_value ffa_memory_tee_reclaim(struct vm_locked to_locked,
					struct vm_locked from_locked,
					ffa_memory_handle_t handle,
					ffa_memory_region_flags_t flags,
					struct mpool *page_pool)
{
	uint32_t request_length = ffa_memory_lender_retrieve_request_init(
		from_locked.vm->mailbox.recv, handle, to_locked.vm->id);
	struct ffa_value tee_ret;
	uint32_t length;
	uint32_t fragment_length;
	uint32_t fragment_offset;
	struct ffa_memory_region *memory_region;
	struct ffa_composite_memory_region *composite;
	uint32_t memory_to_attributes = MM_MODE_R | MM_MODE_W | MM_MODE_X;

	CHECK(request_length <= HF_MAILBOX_SIZE);
	CHECK(from_locked.vm->id == HF_TEE_VM_ID);

	/* Retrieve memory region information from the TEE. */
	tee_ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_RETRIEVE_REQ_32,
				   .arg1 = request_length,
				   .arg2 = request_length});
	if (tee_ret.func == FFA_ERROR_32) {
		dlog_verbose("Got error %d from EL3.\n", tee_ret.arg2);
		return tee_ret;
	}
	if (tee_ret.func != FFA_MEM_RETRIEVE_RESP_32) {
		dlog_verbose(
			"Got %#x from EL3, expected FFA_MEM_RETRIEVE_RESP.\n",
			tee_ret.func);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	length = tee_ret.arg1;
	fragment_length = tee_ret.arg2;

	if (fragment_length > HF_MAILBOX_SIZE || fragment_length > length ||
	    length > sizeof(tee_retrieve_buffer)) {
		dlog_verbose("Invalid fragment length %d/%d (max %d/%d).\n",
			     fragment_length, length, HF_MAILBOX_SIZE,
			     sizeof(tee_retrieve_buffer));
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Copy the first fragment of the memory region descriptor to an
	 * internal buffer.
	 */
	memcpy_s(tee_retrieve_buffer, sizeof(tee_retrieve_buffer),
		 from_locked.vm->mailbox.send, fragment_length);

	/* Fetch the remaining fragments into the same buffer. */
	fragment_offset = fragment_length;
	while (fragment_offset < length) {
		tee_ret = arch_other_world_call(
			(struct ffa_value){.func = FFA_MEM_FRAG_RX_32,
					   .arg1 = (uint32_t)handle,
					   .arg2 = (uint32_t)(handle >> 32),
					   .arg3 = fragment_offset});
		if (tee_ret.func != FFA_MEM_FRAG_TX_32) {
			dlog_verbose(
				"Got %#x (%d) from TEE in response to "
				"FFA_MEM_FRAG_RX, expected FFA_MEM_FRAG_TX.\n",
				tee_ret.func, tee_ret.arg2);
			return tee_ret;
		}
		if (ffa_frag_handle(tee_ret) != handle) {
			dlog_verbose(
				"Got FFA_MEM_FRAG_TX for unexpected handle %#x "
				"in response to FFA_MEM_FRAG_RX for handle "
				"%#x.\n",
				ffa_frag_handle(tee_ret), handle);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		if (ffa_frag_sender(tee_ret) != 0) {
			dlog_verbose(
				"Got FFA_MEM_FRAG_TX with unexpected sender %d "
				"(expected 0).\n",
				ffa_frag_sender(tee_ret));
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		fragment_length = tee_ret.arg3;
		if (fragment_length > HF_MAILBOX_SIZE ||
		    fragment_offset + fragment_length > length) {
			dlog_verbose(
				"Invalid fragment length %d at offset %d (max "
				"%d).\n",
				fragment_length, fragment_offset,
				HF_MAILBOX_SIZE);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		memcpy_s(tee_retrieve_buffer + fragment_offset,
			 sizeof(tee_retrieve_buffer) - fragment_offset,
			 from_locked.vm->mailbox.send, fragment_length);

		fragment_offset += fragment_length;
	}

	memory_region = (struct ffa_memory_region *)tee_retrieve_buffer;

	if (memory_region->receiver_count != 1) {
		/* Only one receiver supported by Hafnium for now. */
		dlog_verbose(
			"Multiple recipients not supported (got %d, expected "
			"1).\n",
			memory_region->receiver_count);
		return ffa_error(FFA_INVALID_PARAMETERS);
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
			"VM %#x attempted to reclaim memory handle %#x "
			"originally sent by VM %#x.\n",
			to_locked.vm->id, handle, memory_region->sender);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);

	/*
	 * Validate that the reclaim transition is allowed for the given memory
	 * region, forward the request to the TEE and then map the memory back
	 * into the caller's stage-2 page table.
	 */
	return ffa_tee_reclaim_check_update(
		to_locked, handle, composite->constituents,
		composite->constituent_count, memory_to_attributes,
		flags & FFA_MEM_RECLAIM_CLEAR, page_pool);
}
