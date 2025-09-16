/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/vm.h"

#include "hf/arch/std.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/ffa/vm.h"
#include "hf/ffa_memory.h"
#include "hf/plat/interrupts.h"

/**
 * The SPMC needs to keep track of some information about NWd VMs.
 * For the time being, only the notifications state structures.
 * Allocation and deallocation of a slot in 'nwd_vms' to and from a given VM
 * will happen upon calls to FFA_NOTIFICATION_BITMAP_CREATE and
 * FFA_NOTIFICATION_BITMAP_DESTROY.
 */
static struct vm nwd_vms[MAX_VMS];

/**
 * All accesses to `nwd_vms` needs to be guarded by this lock.
 */
static struct spinlock nwd_vms_lock_instance = SPINLOCK_INIT;

/**
 * Encapsulates the set of share states while the `nwd_vms_lock_instance` is
 * held.
 */
struct nwd_vms_locked {
	struct vm *nwd_vms;
};

const uint32_t nwd_vms_size = ARRAY_SIZE(nwd_vms);

/** Locks the normal world vms guarding lock. */
static struct nwd_vms_locked nwd_vms_lock(void)
{
	sl_lock(&nwd_vms_lock_instance);

	return (struct nwd_vms_locked){.nwd_vms = nwd_vms};
}

/** Unlocks the normal world vms guarding lock. */
static void nwd_vms_unlock(struct nwd_vms_locked *vms)
{
	CHECK(vms->nwd_vms == nwd_vms);
	vms->nwd_vms = NULL;
	sl_unlock(&nwd_vms_lock_instance);
}

static struct vm_locked ffa_vm_nwd_find_locked(
	struct nwd_vms_locked nwd_vms_locked, ffa_id_t vm_id)
{
	assert(nwd_vms_locked.nwd_vms != NULL);

	for (uint32_t i = 0U; i < nwd_vms_size; i++) {
		if (nwd_vms[i].id == vm_id) {
			return vm_lock(&nwd_vms[i]);
		}
	}

	return (struct vm_locked){.vm = NULL};
}

/**
 * Allocates a NWd VM structure to the VM of given ID.
 * If a VM with the ID already exists return it.
 * Return NULL if it can't allocate a new VM.
 */
struct vm_locked ffa_vm_nwd_alloc(ffa_id_t vm_id)
{
	struct vm_locked vm_locked;
	struct nwd_vms_locked nwd_vms_locked = nwd_vms_lock();

	CHECK(!vm_id_is_current_world(vm_id));

	/* Check if a VM with `vm_id` already exists and returns it. */
	vm_locked = ffa_vm_nwd_find_locked(nwd_vms_locked, vm_id);
	if (vm_locked.vm != NULL) {
		goto out;
	}

	/* Get first empty slot in `nwd_vms` to create VM. */
	vm_locked = ffa_vm_nwd_find_locked(nwd_vms_locked, HF_INVALID_VM_ID);
	if (vm_locked.vm == NULL) {
		/* NULL means there are no slots in `nwd_vms`. */
		goto out;
	}

	/*
	 * Note: VM struct for Nwd VMs is only partially initialized, to the
	 * extend of what's currently used by the SPMC (VM ID, waiter list).
	 */
	vm_locked.vm->id = vm_id;

out:
	nwd_vms_unlock(&nwd_vms_locked);

	return vm_locked;
}

void ffa_vm_nwd_free(struct vm_locked to_destroy_locked)
{
	struct vm *vm = to_destroy_locked.vm;
	/*
	 * Free the VM slot if notifications are disabled and mailbox is not
	 * mapped.
	 */
	if (!vm_id_is_current_world(vm->id) && vm->id != HF_HYPERVISOR_VM_ID &&
	    !vm->notifications.enabled && vm->mailbox.send == NULL &&
	    vm->mailbox.recv == NULL) {
		to_destroy_locked.vm->id = HF_INVALID_VM_ID;
		to_destroy_locked.vm->vcpu_count = 0U;
	}
}

void ffa_vm_init(struct mpool *ppool)
{
	(void)ppool;
	struct vm *other_world = vm_find(HF_OTHER_WORLD_ID);

	/* Init NWd VMs structures for use of Notifications interfaces. */
	for (uint32_t i = 0; i < nwd_vms_size; i++) {
		/*
		 * Note that vm_init() is not called on nwd_vms. This means that
		 * dynamically allocated structures, such as vcpus, are left
		 * as NULL in the nwd_vms structures. This is okay, since as of
		 * today, the vcpu structures are not used. This also helps
		 * reduce memory foot print. A slot in 'nwd_vms' is considered
		 * available if its id is HF_INVALID_VM_ID.
		 */
		nwd_vms[i].id = HF_INVALID_VM_ID;
		nwd_vms[i].vcpu_count = MAX_CPUS;
		vm_notifications_init(&nwd_vms[i]);

		/* Give them the same version as the Hypervisor. */
		nwd_vms[i].ffa_version = other_world->ffa_version;
	}
}

bool ffa_vm_managed_exit_supported(struct vm *vm)
{
	return (vm->ns_interrupts_action == NS_ACTION_ME);
}

struct vm_locked ffa_vm_find_locked(ffa_id_t vm_id)
{
	struct vm_locked to_ret_locked;

	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	struct nwd_vms_locked nwd_vms_locked = nwd_vms_lock();

	to_ret_locked = ffa_vm_nwd_find_locked(nwd_vms_locked, vm_id);

	nwd_vms_unlock(&nwd_vms_locked);

	return to_ret_locked;
}

struct vm_locked ffa_vm_find_locked_create(ffa_id_t vm_id)
{
	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	return ffa_vm_nwd_alloc(vm_id);
}

bool ffa_vm_notifications_info_get(uint16_t *ids, uint32_t *ids_count,
				   uint32_t *lists_sizes, uint32_t *lists_count,
				   const uint32_t ids_count_max)
{
	struct nwd_vms_locked nwd_vms_locked = nwd_vms_lock();
	struct vm_locked other_world_locked = vm_find_locked(HF_OTHER_WORLD_ID);
	/*
	 * Variable to save return from 'vm_notifications_info_get'. To be
	 * returned and used as indicator that scheduler should conduct more
	 * calls to retrieve info of pending notifications.
	 */
	bool list_full_and_more_pending = false;

	CHECK(other_world_locked.vm != NULL);

	list_full_and_more_pending = vm_notifications_info_get(
		other_world_locked, ids, ids_count, lists_sizes, lists_count,
		ids_count_max);

	vm_unlock(&other_world_locked);

	for (ffa_vm_count_t i = 0;
	     i < nwd_vms_size && !list_full_and_more_pending; i++) {
		if (nwd_vms[i].id != HF_INVALID_VM_ID) {
			struct vm_locked vm_locked = vm_lock(&nwd_vms[i]);

			list_full_and_more_pending = vm_notifications_info_get(
				vm_locked, ids, ids_count, lists_sizes,
				lists_count, ids_count_max);

			vm_unlock(&vm_locked);
		}
	}

	nwd_vms_unlock(&nwd_vms_locked);

	return list_full_and_more_pending;
}

void ffa_vm_disable_interrupts(struct vm_locked vm_locked)
{
	uint32_t core_pos = arch_find_core_pos();

	/* Gracefully disable interrupts. */
	dlog_verbose("Interrupts belonging to SP %x disabled\n",
		     vm_locked.vm->id);

	for (uint32_t i = 0; i < VM_MANIFEST_MAX_INTERRUPTS; i++) {
		struct interrupt_descriptor int_desc;

		int_desc = vm_locked.vm->interrupt_desc[i];
		if (!int_desc.valid) {
			break;
		}
		plat_interrupts_disable(int_desc.interrupt_id, core_pos);
	}
}

/**
 * Reclaim all resources belonging to VM in aborted state.
 */
void ffa_vm_free_resources(struct vm_locked vm_locked, struct mpool *ppool)
{
	/*
	 * Gracefully disable all interrupts belonging to SP.
	 */
	ffa_vm_disable_interrupts(vm_locked);

	/*
	 * Reclaim all memory regions shared or lent by this partition.
	 * Relinquish all memory regions shared with or lent to this partition
	 * by other endpoints.
	 */
	ffa_memory_reclaim_relinquish_vm_regions(vm_locked, ppool);

	/*
	 * Unmap RX/TX buffer and all memory as well as device regions declared
	 * by this partition in its manifest. This shall be done afer SPMC was
	 * given the change to perform any reclaim or relinquish actions on
	 * behalf of aborting partition.
	 */
	vm_unmap_memory_regions(vm_locked, ppool);
}

/**
 * Traverses the NWd VMs and determines if any RX/TX buffers
 * are mapped, if so, updates the provided address map descriptor.
 * AMDs generated from this traversal will have the endpoint_id
 * set to HF_SPMC_VM_ID to indicate that all SPs have potential
 * access to these memory regions. The current index parameter
 * is updated to allow for continuous traversal of the NWd VMs
 * structure. The NWd ID parameter is used to determine which
 * NWd VM is connected to the RX/TX buffer being reported.
 */
bool ffa_get_nwd_rxtx_buffer_info(struct ffa_address_map_desc *amd,
				  bool check_rx_buffer, bool *buffer_mapped,
				  uint16_t *curr_index, ffa_id_t *nwd_id)
{
	bool success = false;
	struct nwd_vms_locked nwd_vms_locked;

	/* Make sure we have valid parameters */
	assert(amd != NULL);
	assert(buffer_mapped != NULL);
	assert(curr_index != NULL);
	assert(nwd_id != NULL);

	nwd_vms_locked = nwd_vms_lock();

	/* Loop through the list of normal world vms. */
	for (; *curr_index < nwd_vms_size; *curr_index += 1) {
		ffa_amd_permissions_t permissions;
		struct vm_locked vm_locked;

		/* Make sure the vm we are checking is valid. */
		if (nwd_vms[*curr_index].id == HF_INVALID_VM_ID) {
			continue;
		}

		success = true;
		vm_locked = vm_lock(&nwd_vms[*curr_index]);

		/*
		 * Determine if either buffer has been mapped. If so,
		 * an AMD is guaranteed to be generated.
		 */
		*buffer_mapped = vm_locked.vm->mailbox.recv != NULL ||
				 vm_locked.vm->mailbox.send != NULL;
		if (*buffer_mapped) {
			*nwd_id = vm_locked.vm->id;
		}

		/* If the RX or TX buffer is mapped */
		if (check_rx_buffer && vm_locked.vm->mailbox.recv != NULL) {
			/*
			 * The RX buffer from the SPMC's perspective has R/W
			 * permissions. Due to the fact that all SPs have
			 * potential access to the RX buffer, it will have both
			 * privileged and unprivileged permissions.
			 */
			permissions = ffa_memory_amd_permissions_from_mm_mode(
				(MM_MODE_R | MM_MODE_W), true);

			/* Setup the address map descriptor. */
			ffa_ns_res_info_get_amd_init(
				amd, (uintptr_t)vm_locked.vm->mailbox.recv,
				(HF_MAILBOX_SIZE / FFA_PAGE_SIZE), permissions,
				HF_SPMC_VM_ID,
				FFA_NS_RES_INFO_GET_INDIRECTLY_ACC_FLAG);
		} else if (vm_locked.vm->mailbox.send != NULL) {
			/*
			 * The TX buffer from the SPMC's perspective has R
			 * permissions. Due to the fact that all SPs have
			 * potential access to the TX buffer, it will have both
			 * privileged and unprivileged permissions.
			 */
			permissions = ffa_memory_amd_permissions_from_mm_mode(
				MM_MODE_R, true);

			/* Setup the address map descriptor. */
			ffa_ns_res_info_get_amd_init(
				amd, (uintptr_t)vm_locked.vm->mailbox.send,
				(HF_MAILBOX_SIZE / FFA_PAGE_SIZE), permissions,
				HF_SPMC_VM_ID,
				FFA_NS_RES_INFO_GET_INDIRECTLY_ACC_FLAG);
		}

		vm_unlock(&vm_locked);
		break;
	}

	nwd_vms_unlock(&nwd_vms_locked);

	return success;
}
