/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/vm.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/ffa.h"
#include "hf/layout.h"
#include "hf/plat/iommu.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

static struct vm vms[MAX_VMS];
static struct vm other_world;
static ffa_vm_count_t vm_count;
static struct vm *first_boot_vm;

struct vm *vm_init(ffa_vm_id_t id, ffa_vcpu_count_t vcpu_count,
		   struct mpool *ppool)
{
	uint32_t i;
	struct vm *vm;

	if (id == HF_OTHER_WORLD_ID) {
		vm = &other_world;
	} else {
		uint16_t vm_index = id - HF_VM_ID_OFFSET;

		CHECK(id >= HF_VM_ID_OFFSET);
		CHECK(vm_index < ARRAY_SIZE(vms));
		vm = &vms[vm_index];
	}

	memset_s(vm, sizeof(*vm), 0, sizeof(*vm));

	list_init(&vm->mailbox.waiter_list);
	list_init(&vm->mailbox.ready_list);
	sl_init(&vm->lock);

	vm->id = id;
	vm->vcpu_count = vcpu_count;
	vm->mailbox.state = MAILBOX_STATE_EMPTY;
	atomic_init(&vm->aborting, false);

	if (!mm_vm_init(&vm->ptable, ppool)) {
		return NULL;
	}

	/* Initialise waiter entries. */
	for (i = 0; i < MAX_VMS; i++) {
		vm->wait_entries[i].waiting_vm = vm;
		list_init(&vm->wait_entries[i].wait_links);
		list_init(&vm->wait_entries[i].ready_links);
	}

	/* Do basic initialization of vCPUs. */
	for (i = 0; i < vcpu_count; i++) {
		vcpu_init(vm_get_vcpu(vm, i), vm);
	}

	return vm;
}

bool vm_init_next(ffa_vcpu_count_t vcpu_count, struct mpool *ppool,
		  struct vm **new_vm)
{
	if (vm_count >= MAX_VMS) {
		return false;
	}

	/* Generate IDs based on an offset, as low IDs e.g., 0, are reserved */
	*new_vm = vm_init(vm_count + HF_VM_ID_OFFSET, vcpu_count, ppool);
	if (*new_vm == NULL) {
		return false;
	}
	++vm_count;

	return true;
}

ffa_vm_count_t vm_get_count(void)
{
	return vm_count;
}

/**
 * Returns a pointer to the VM with the corresponding id.
 */
struct vm *vm_find(ffa_vm_id_t id)
{
	uint16_t index;

	if (id == HF_OTHER_WORLD_ID) {
		if (other_world.id == HF_OTHER_WORLD_ID) {
			return &other_world;
		}
		return NULL;
	}

	/* Check that this is not a reserved ID. */
	if (id < HF_VM_ID_OFFSET) {
		return NULL;
	}

	index = id - HF_VM_ID_OFFSET;

	return vm_find_index(index);
}

/**
 * Returns a pointer to the VM at the specified index.
 */
struct vm *vm_find_index(uint16_t index)
{
	/* Ensure the VM is initialized. */
	if (index >= vm_count) {
		return NULL;
	}

	return &vms[index];
}

/**
 * Locks the given VM and updates `locked` to hold the newly locked VM.
 */
struct vm_locked vm_lock(struct vm *vm)
{
	struct vm_locked locked = {
		.vm = vm,
	};

	sl_lock(&vm->lock);

	return locked;
}

/**
 * Locks two VMs ensuring that the locking order is according to the locks'
 * addresses.
 */
struct two_vm_locked vm_lock_both(struct vm *vm1, struct vm *vm2)
{
	struct two_vm_locked dual_lock;

	sl_lock_both(&vm1->lock, &vm2->lock);
	dual_lock.vm1.vm = vm1;
	dual_lock.vm2.vm = vm2;

	return dual_lock;
}

/**
 * Unlocks a VM previously locked with vm_lock, and updates `locked` to reflect
 * the fact that the VM is no longer locked.
 */
void vm_unlock(struct vm_locked *locked)
{
	sl_unlock(&locked->vm->lock);
	locked->vm = NULL;
}

/**
 * Get the vCPU with the given index from the given VM.
 * This assumes the index is valid, i.e. less than vm->vcpu_count.
 */
struct vcpu *vm_get_vcpu(struct vm *vm, ffa_vcpu_index_t vcpu_index)
{
	CHECK(vcpu_index < vm->vcpu_count);
	return &vm->vcpus[vcpu_index];
}

/**
 * Gets `vm`'s wait entry for waiting on the `for_vm`.
 */
struct wait_entry *vm_get_wait_entry(struct vm *vm, ffa_vm_id_t for_vm)
{
	uint16_t index;

	CHECK(for_vm >= HF_VM_ID_OFFSET);
	index = for_vm - HF_VM_ID_OFFSET;
	CHECK(index < MAX_VMS);

	return &vm->wait_entries[index];
}

/**
 * Gets the ID of the VM which the given VM's wait entry is for.
 */
ffa_vm_id_t vm_id_for_wait_entry(struct vm *vm, struct wait_entry *entry)
{
	uint16_t index = entry - vm->wait_entries;

	return index + HF_VM_ID_OFFSET;
}

/**
 * Return whether the given VM ID represents an entity in the current world:
 * i.e. the hypervisor or a normal world VM when running in the normal world, or
 * the SPM or an SP when running in the secure world.
 */
bool vm_id_is_current_world(ffa_vm_id_t vm_id)
{
	return (vm_id & HF_VM_ID_WORLD_MASK) !=
	       (HF_OTHER_WORLD_ID & HF_VM_ID_WORLD_MASK);
}

/**
 * Map a range of addresses to the VM in both the MMU and the IOMMU.
 *
 * mm_vm_defrag should always be called after a series of page table updates,
 * whether they succeed or fail. This is because on failure extra page table
 * entries may have been allocated and then not used, while on success it may be
 * possible to compact the page table by merging several entries into a block.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 *
 */
bool vm_identity_map(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
		     uint32_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	if (!vm_identity_prepare(vm_locked, begin, end, mode, ppool)) {
		return false;
	}

	vm_identity_commit(vm_locked, begin, end, mode, ppool, ipa);

	return true;
}

/**
 * Prepares the given VM for the given address mapping such that it will be able
 * to commit the change without failure.
 *
 * In particular, multiple calls to this function will result in the
 * corresponding calls to commit the changes to succeed.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 */
bool vm_identity_prepare(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			 uint32_t mode, struct mpool *ppool)
{
	return mm_vm_identity_prepare(&vm_locked.vm->ptable, begin, end, mode,
				      ppool);
}

/**
 * Commits the given address mapping to the VM assuming the operation cannot
 * fail. `vm_identity_prepare` must used correctly before this to ensure
 * this condition.
 */
void vm_identity_commit(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			uint32_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	mm_vm_identity_commit(&vm_locked.vm->ptable, begin, end, mode, ppool,
			      ipa);
	plat_iommu_identity_map(vm_locked, begin, end, mode);
}

/**
 * Unmap a range of addresses from the VM.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 */
bool vm_unmap(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
	      struct mpool *ppool)
{
	uint32_t mode = MM_MODE_UNMAPPED_MASK;

	return vm_identity_map(vm_locked, begin, end, mode, ppool, NULL);
}

/**
 * Unmaps the hypervisor pages from the given page table.
 */
bool vm_unmap_hypervisor(struct vm_locked vm_locked, struct mpool *ppool)
{
	/* TODO: If we add pages dynamically, they must be included here too. */
	return vm_unmap(vm_locked, layout_text_begin(), layout_text_end(),
			ppool) &&
	       vm_unmap(vm_locked, layout_rodata_begin(), layout_rodata_end(),
			ppool) &&
	       vm_unmap(vm_locked, layout_data_begin(), layout_data_end(),
			ppool);
}

/**
 * Gets the first partition to boot, according to Boot Protocol from FFA spec.
 */
struct vm *vm_get_first_boot(void)
{
	return first_boot_vm;
}

/**
 * Insert in boot list, sorted by `boot_order` parameter in the vm structure
 * and rooted in `first_boot_vm`.
 */
void vm_update_boot(struct vm *vm)
{
	struct vm *current = NULL;
	struct vm *previous = NULL;

	if (first_boot_vm == NULL) {
		first_boot_vm = vm;
		return;
	}

	current = first_boot_vm;

	while (current != NULL && current->boot_order >= vm->boot_order) {
		previous = current;
		current = current->next_boot;
	}

	if (previous != NULL) {
		previous->next_boot = vm;
	} else {
		first_boot_vm = vm;
	}

	vm->next_boot = current;
}
