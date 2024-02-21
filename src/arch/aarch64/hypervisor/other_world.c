/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/other_world.h"

#include "hf/arch/mmu.h"
#include "hf/arch/plat/ffa.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "smc.h"

bool arch_other_world_vm_init(struct vm *other_world_vm,
			      const struct boot_params *params,
			      struct mpool *ppool)
{
	const char *err_msg =
		"Unable to initialise address space for Other world VM.\n";
	struct vm_locked other_world_vm_locked;
	bool ret = false;
	uint32_t i;

	other_world_vm_locked = vm_lock(other_world_vm);

	/* Enabling all communication methods for the other world. */
	other_world_vm->messaging_method =
		FFA_PARTITION_DIRECT_REQ_SEND | FFA_PARTITION_DIRECT_REQ2_SEND;

	/*
	 * If Hafnium is NWd Hypervisor, allow other_world_VM (SPMC) to
	 * receive requests.
	 * When Hafnium is SPMC, other_world_vm not allowed to receive requests
	 * from SPs.
	 */
#if SECURE_WORLD == 0
	other_world_vm->messaging_method |= FFA_PARTITION_DIRECT_REQ2_RECV;
	other_world_vm->messaging_method |= FFA_PARTITION_DIRECT_REQ_RECV;
#endif

	/* Map NS mem ranges to "Other world VM" Stage-2 PTs. */
	for (i = 0; i < params->ns_mem_ranges_count; i++) {
		if (!vm_identity_map(
			    other_world_vm_locked,
			    params->ns_mem_ranges[i].begin,
			    params->ns_mem_ranges[i].end,
			    MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS,
			    ppool, NULL)) {
			dlog_error("Normal Memory: %s", err_msg);
			goto out;
		}
	}

	/*
	 * Map NS device mem ranges to "Other world VM" Stage-2 PTs to allow
	 * for memory sharing operations from NWd to SWd.
	 */
	for (i = 0; i < params->ns_device_mem_ranges_count; i++) {
		if (!vm_identity_map(
			    other_world_vm_locked,
			    params->ns_device_mem_ranges[i].begin,
			    params->ns_device_mem_ranges[i].end,
			    MM_MODE_R | MM_MODE_W | MM_MODE_D | MM_MODE_NS,
			    ppool, NULL)) {
			dlog_error("Device Memory: %s", err_msg);
			goto out;
		}
	}

	/*
	 * Force the hypervisor's version to be same as ours.
	 * FF-A version at hypervisor's initialization is not getting to the
	 * SPMC.
	 * TODO: fix the described above and delete this.
	 */
	other_world_vm->ffa_version = FFA_VERSION_COMPILED;

	ret = true;

out:
	vm_unlock(&other_world_vm_locked);

	return ret;
}

struct ffa_value arch_other_world_call(struct ffa_value args)
{
	return smc_ffa_call(args);
}

struct ffa_value arch_other_world_call_ext(struct ffa_value args)
{
	return smc_ffa_call_ext(args);
}

/**
 * Obtain a lock on the other world VM, making sure it is
 * locked in the correct order relative to the owner VM in order to avoid a
 * deadlock.
 */
static struct vm_locked lock_other_world(struct vm_locked owner_vm_locked)
{
	struct vm *other_world_vm;
	struct two_vm_locked both;

	if (owner_vm_locked.vm->id == HF_OTHER_WORLD_ID) {
		return owner_vm_locked;
	}

	other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	both = vm_lock_both_in_order(owner_vm_locked, other_world_vm);

	return both.vm2;
}

static void unlock_other_world(struct vm_locked owner_vm_locked,
			       struct vm_locked other_world_locked)
{
	if (owner_vm_locked.vm->id != other_world_locked.vm->id) {
		vm_unlock(&other_world_locked);
	}
}

/**
 * Unmap rxtx buffers from other world so that they cannot be used for memory
 * sharing operations from NWd, or FFA_RXTX_MAP in another instance.
 *
 * Fails if the given addresses are not already mapped in the other world page
 * tables.
 *
 * Returns `FFA_DENIED` if the send/recv pages are not mapped in normal world
 * pages tables, or are mapped with incorrect permissions.
 *
 * Returns `FFA_ABORTED` if unmapping the send/recv pages from the normal world
 * page tables fails.
 */
struct ffa_value arch_other_world_vm_configure_rxtx_map(
	struct vm_locked vm_locked, struct mpool *local_page_pool,
	paddr_t pa_send_begin, paddr_t pa_send_end, paddr_t pa_recv_begin,
	paddr_t pa_recv_end)
{
	struct ffa_value ret;
	uint32_t send_mode;
	uint32_t recv_mode;
	struct vm_locked other_world_locked;
	const uint32_t expected_mode =
		MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS;

	other_world_locked = lock_other_world(vm_locked);
	assert(other_world_locked.vm != NULL);

	/*
	 * Check that the memory is mapped in the NWd set of page
	 * tables.
	 */
	if (!vm_mem_get_mode(other_world_locked, ipa_from_pa(pa_send_begin),
			     ipa_from_pa(pa_send_end), &send_mode)) {
		ret = ffa_error(FFA_DENIED);
		dlog_error("%s: send page not mapped in NWd VM\n", __func__);
		goto out_unlock;
	}
	if (!vm_mem_get_mode(other_world_locked, ipa_from_pa(pa_recv_begin),
			     ipa_from_pa(pa_recv_end), &recv_mode)) {
		ret = ffa_error(FFA_DENIED);
		dlog_error("%s: recv page not mapped in NWd VM\n", __func__);
		goto out_unlock;
	}

	if ((send_mode & expected_mode) != expected_mode) {
		ret = ffa_error(FFA_DENIED);
		dlog_error("%s: send page is invalid (expected %#x, got %#x)\n",
			   __func__, expected_mode, send_mode);
		goto out_unlock;
	}
	if ((recv_mode & expected_mode) != expected_mode) {
		ret = ffa_error(FFA_DENIED);
		dlog_error("%s: recv page is invalid (expected %#x, got %#x)\n",
			   __func__, expected_mode, recv_mode);
		goto out_unlock;
	}

	/*
	 * Unmap the memory from the NWd page tables, to prevent that memory
	 * being used in memory sharing operations from the NWd, or in further
	 * `FFA_RXTX_MAP` calls.
	 */
	if (!vm_unmap(other_world_locked, pa_send_begin, pa_send_end,
		      local_page_pool)) {
		dlog_error("%s: cannot unmap send page from NWd VM\n",
			   __func__);
		ret = ffa_error(FFA_ABORTED);
		goto out_unlock;
	}
	if (!vm_unmap(other_world_locked, pa_recv_begin, pa_recv_end,
		      local_page_pool)) {
		ret = ffa_error(FFA_ABORTED);
		dlog_error("%s: cannot unmap recv page from NWd VM\n",
			   __func__);
		goto out_unlock;
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out_unlock:
	unlock_other_world(vm_locked, other_world_locked);
	return ret;
}

/**
 * Remap rxtx buffers to other world so that they can be used for memory sharing
 * operations from NWd, or FFA_RXTX_MAP in another instance.
 *
 * Returns `FFA_ABORTED` if mapping the send/recv pages in the normal world page
 * tables fails.
 */
struct ffa_value arch_other_world_vm_configure_rxtx_unmap(
	struct vm_locked vm_locked, struct mpool *local_page_pool,
	paddr_t pa_send_begin, paddr_t pa_send_end, paddr_t pa_recv_begin,
	paddr_t pa_recv_end)
{
	struct vm_locked other_world_locked = lock_other_world(vm_locked);

	if (other_world_locked.vm == NULL) {
		return ffa_error(FFA_ABORTED);
	}

	/* Remap to other world page tables. */
	if (!vm_identity_map(other_world_locked, pa_send_begin, pa_send_end,
			     MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS,
			     local_page_pool, NULL)) {
		dlog_error(
			"%s: unable to remap send page to other world page "
			"tables\n",
			__func__);
		return ffa_error(FFA_ABORTED);
	}

	if (!vm_identity_map(other_world_locked, pa_recv_begin, pa_recv_end,
			     MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS,
			     local_page_pool, NULL)) {
		dlog_error(
			"%s: unable to remap recv page to other world page "
			"tables\n",
			__func__);
		CHECK(vm_unmap(other_world_locked, pa_send_begin, pa_send_end,
			       local_page_pool));
		return ffa_error(FFA_ABORTED);
	}

	unlock_other_world(vm_locked, other_world_locked);
	return (struct ffa_value){.func = FFA_SUCCESS_32};
}
