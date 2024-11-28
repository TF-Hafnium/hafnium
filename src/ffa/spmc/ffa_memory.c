/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa_memory.h"

#include "hf/arch/mmu.h"

#include "hf/ffa/ffa_memory.h"
#include "hf/ffa_internal.h"
#include "hf/vm.h"

#include "sysregs.h"

enum ffa_memory_handle_allocator plat_ffa_memory_handle_allocator(void)
{
	return FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;
}

/** Check validity of the FF-A memory send function attempt. */
bool plat_ffa_is_memory_send_valid(ffa_id_t receiver, ffa_id_t sender,
				   uint32_t share_func, bool multiple_borrower)
{
	const bool is_receiver_sp = vm_id_is_current_world(receiver);
	const bool is_sender_sp = vm_id_is_current_world(sender);

	/*
	 * SPs can only share/lend/donate to another SP.
	 * VMs can send memory to SPs.
	 * In a multiple borrower operation, VMs might provide descriptors
	 * of other VMs.
	 * Refer to the section 1.4 of the FF-A v1.2 Memory Management
	 * supplement ALP0 specification.
	 */
	switch (share_func) {
	case FFA_MEM_DONATE_64:
	case FFA_MEM_DONATE_32:
	case FFA_MEM_LEND_64:
	case FFA_MEM_LEND_32:
		return is_receiver_sp;
	case FFA_MEM_SHARE_64:
	case FFA_MEM_SHARE_32: {
		bool result = (is_sender_sp && is_receiver_sp) ||
			      (!is_sender_sp && !multiple_borrower &&
			       is_receiver_sp) ||
			      (!is_sender_sp && multiple_borrower);

		if (!result) {
			dlog_verbose(
				"SPMC only supports memory operations to a "
				"single SP, or multiple borrowers with mixed "
				"world borrowers.\n");
		}
		return result;
	}
	default:
		return false;
	}
}

uint32_t plat_ffa_other_world_mode(void)
{
	return MM_MODE_NS;
}

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current)
{
	/* FFA_MEM_PERM_SET/GET is only valid before SPs are initialized */
	return has_vhe_support() && (current->rt_model == RTM_SP_INIT);
}

bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current)
{
	/* FFA_MEM_PERM_SET/GET is only valid before SPs are initialized */
	return has_vhe_support() && (current->rt_model == RTM_SP_INIT);
}

struct ffa_value plat_ffa_other_world_mem_send(
	struct vm *from, uint32_t share_func,
	struct ffa_memory_region **memory_region, uint32_t length,
	uint32_t fragment_length, struct mpool *page_pool)
{
	struct ffa_value ret;
	struct vm_locked from_locked = vm_lock(from);

	ret = ffa_memory_send(from_locked, *memory_region, length,
			      fragment_length, share_func, page_pool);
	/*
	 * ffa_memory_send takes ownership of the memory_region, so
	 * make sure we don't free it.
	 */
	*memory_region = NULL;

	vm_unlock(&from_locked);

	return ret;
}

/*
 * SPMC handles its memory share requests internally, so no forwarding of the
 * request is required.
 */
struct ffa_value plat_ffa_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	(void)handle;
	(void)flags;
	(void)page_pool;
	(void)to;

	dlog_verbose("Invalid handle %#lx for FFA_MEM_RECLAIM.\n", handle);
	return ffa_error(FFA_INVALID_PARAMETERS);
}

struct ffa_value plat_ffa_other_world_mem_send_continue(
	struct vm *from, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct mpool *page_pool)
{
	(void)from;
	(void)fragment;
	(void)fragment_length;
	(void)handle;
	(void)page_pool;

	return ffa_error(FFA_INVALID_PARAMETERS);
}

/**
 * Update the memory region attributes with the security state bit based on the
 * supplied mode.
 */
ffa_memory_attributes_t plat_ffa_memory_add_security_bit_from_mode(
	ffa_memory_attributes_t attributes, uint32_t mode)
{
	ffa_memory_attributes_t ret = attributes;

	if ((mode & MM_MODE_NS) != 0) {
		ret.security = FFA_MEMORY_SECURITY_NON_SECURE;
	}

	return ret;
}
