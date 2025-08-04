/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/vm.h"

#include "hf/arch/spinlock.h"
#include "hf/arch/vm.h"

#include "hf/api.h"
#include "hf/assert.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/layout.h"
#include "hf/plat/iommu.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

static struct vm vms[MAX_VMS];
static struct vm other_world;
static ffa_vm_count_t vm_count;

/**
 * The `boot_list` is a special entry in the circular linked list maintained by
 * the partition manager and serves as both the start and end of the list.
 */
static struct list_entry boot_list = LIST_INIT(boot_list);

/**
 * Counters on the status of notifications in the system. It helps to improve
 * the information retrieved by the receiver scheduler.
 */
static struct {
	/** Counts notifications pending. */
	uint32_t pending_count;
	/**
	 * Counts notifications pending, that have been retrieved by the
	 * receiver scheduler.
	 */
	uint32_t info_get_retrieved_count;
	struct spinlock lock;
} all_notifications_state;

static bool vm_init_mm(struct vm *vm, struct mpool *ppool)
{
	return arch_vm_init_mm(vm, ppool) && arch_vm_iommu_init_mm(vm, ppool);
}

static bool vm_init_helper(struct vm *vm, ffa_id_t id,
			   ffa_vcpu_count_t vcpu_count, struct mpool *ppool,
			   bool el0_partition, uint8_t dma_device_count)
{
	uint32_t i;
	size_t vcpu_ppool_entries = (align_up(sizeof(struct vcpu) * vcpu_count,
					      MM_PPOOL_ENTRY_SIZE) /
				     MM_PPOOL_ENTRY_SIZE);

	memset_s(vm, sizeof(*vm), 0, sizeof(*vm));

	sl_init(&vm->lock);

	vm->id = id;
	vm->vcpu_count = vcpu_count;

	/* Reallocate from memory pool */
	vm->vcpus = (struct vcpu *)mpool_alloc_contiguous(
		ppool, vcpu_ppool_entries, 1);
	CHECK(vm->vcpus != NULL);

	vm->mailbox.state = MAILBOX_STATE_EMPTY;
	vm->el0_partition = el0_partition;
	vm->dma_device_count = dma_device_count;

	if (!vm_init_mm(vm, ppool)) {
		dlog_error("Failed to (re)build page tables\n");
		return false;
	}

	/*
	 * Do basic initialization of vCPUs, i.e. All vCPUs of the partition
	 * shall be in CREATED state.
	 */
	for (i = 0; i < vcpu_count; i++) {
		vcpu_init(vm_get_vcpu(vm, i), vm);
	}

	vm_notifications_init(vm, vcpu_count, ppool);
	list_init(&vm->boot_list_node);

	return true;
}

struct vm *vm_init(ffa_id_t id, ffa_vcpu_count_t vcpu_count,
		   struct mpool *ppool, bool el0_partition,
		   uint8_t dma_device_count)
{
	struct vm *vm;

	if (id == HF_OTHER_WORLD_ID) {
		CHECK(el0_partition == false);
		vm = &other_world;
	} else {
		uint16_t vm_index = id - HF_VM_ID_OFFSET;

		CHECK(id >= HF_VM_ID_OFFSET);
		CHECK(vm_index < ARRAY_SIZE(vms));
		vm = &vms[vm_index];
	}

	if (vm_init_helper(vm, id, vcpu_count, ppool, el0_partition,
			   dma_device_count)) {
		return vm;
	}

	return NULL;
}

bool vm_init_next(ffa_vcpu_count_t vcpu_count, struct mpool *ppool,
		  struct vm **new_vm, bool el0_partition,
		  uint8_t dma_device_count)
{
	if (vm_count >= MAX_VMS) {
		return false;
	}

	/* Generate IDs based on an offset, as low IDs e.g., 0, are reserved */
	*new_vm = vm_init(vm_count + HF_VM_ID_OFFSET, vcpu_count, ppool,
			  el0_partition, dma_device_count);
	if (*new_vm == NULL) {
		return false;
	}
	++vm_count;

	return true;
}

bool vm_reinit(struct vm *vm, struct mpool *ppool)
{
	size_t vcpu_ppool_entries;
	bool ret;

	CHECK(vm != NULL);

	vcpu_ppool_entries = (align_up(sizeof(struct vcpu) * (vm->vcpu_count),
				       MM_PPOOL_ENTRY_SIZE) /
			      MM_PPOOL_ENTRY_SIZE);

	/* Free the chunk of memory and add back to memory pool. */
	assert(vm->vcpus != NULL);
	mpool_add_chunk(ppool, vm->vcpus, vcpu_ppool_entries);

	ret = vm_init_helper(vm, vm->id, vm->vcpu_count, ppool,
			     vm->el0_partition, vm->dma_device_count);

	if (!ret) {
		dlog_error("Failed to re-initialize VM.\n");
		return false;
	}

	return true;
}

ffa_vm_count_t vm_get_count(void)
{
	return vm_count;
}

/**
 * Returns a pointer to the VM with the corresponding id.
 */
struct vm *vm_find(ffa_id_t id)
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
 * Returns a locked instance of the VM with the corresponding id.
 */
struct vm_locked vm_find_locked(ffa_id_t id)
{
	struct vm *vm = vm_find(id);

	if (vm != NULL) {
		return vm_lock(vm);
	}

	return (struct vm_locked){.vm = NULL};
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
 * Locks two VMs ensuring that the locking order is according to the locks'
 * addresses, given `vm1` is already locked.
 */
struct two_vm_locked vm_lock_both_in_order(struct vm_locked vm1, struct vm *vm2)
{
	struct spinlock *sl1 = &vm1.vm->lock;
	struct spinlock *sl2 = &vm2->lock;

	/*
	 * Use `sl_lock`/`sl_unlock` directly rather than
	 * `vm_lock`/`vm_unlock` because `vm_unlock` sets the vm field
	 * to NULL.
	 */
	if (sl1 < sl2) {
		sl_lock(sl2);
	} else {
		sl_unlock(sl1);
		sl_lock(sl2);
		sl_lock(sl1);
	}

	return (struct two_vm_locked){
		.vm1 = vm1,
		.vm2 = (struct vm_locked){.vm = vm2},
	};
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
 * Checks whether the given `to` VM's mailbox is currently busy.
 */
bool vm_is_mailbox_busy(struct vm_locked to)
{
	return to.vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	       to.vm->mailbox.recv == NULL;
}

/**
 * Checks if mailbox is currently owned by the other world.
 */
bool vm_is_mailbox_other_world_owned(struct vm_locked to)
{
	return to.vm->mailbox.state == MAILBOX_STATE_OTHER_WORLD_OWNED;
}

/**
 * Return whether the given VM ID represents an entity in the current world:
 * i.e. the hypervisor or a normal world VM when running in the normal world, or
 * the SPM or an SP when running in the secure world.
 */
bool vm_id_is_current_world(ffa_id_t vm_id)
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
		     mm_mode_t mode, struct mpool *ppool, ipaddr_t *ipa)
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
			 mm_mode_t mode, struct mpool *ppool)
{
	return arch_vm_identity_prepare(vm_locked, begin, end, mode, ppool);
}

/**
 * Commits the given address mapping to the VM assuming the operation cannot
 * fail. `vm_identity_prepare` must used correctly before this to ensure
 * this condition.
 */
void vm_identity_commit(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			mm_mode_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	arch_vm_identity_commit(vm_locked, begin, end, mode, ppool, ipa);
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
	return arch_vm_unmap(vm_locked, begin, end, ppool);
}

/**
 * Defrag page tables for an EL0 partition or for a VM.
 */
void vm_ptable_defrag(struct vm_locked vm_locked, struct mpool *ppool)
{
	arch_vm_ptable_defrag(vm_locked, ppool);
}

/**
 * Free all page tables associated with a partition.
 */
void vm_free_ptables(struct vm *vm, struct mpool *ppool)
{
	arch_vm_fini_mm(vm, ppool);
	arch_vm_iommu_fini_mm(vm, ppool);
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
			ppool) &&
	       vm_unmap(vm_locked, layout_stacks_begin(), layout_stacks_end(),
			ppool);
}

void vm_unmap_rxtx(struct vm_locked vm_locked, struct mpool *ppool)
{
	struct vm *vm = vm_locked.vm;
	struct mm_stage1_locked mm_stage1_locked;
	paddr_t send_pa_begin;
	paddr_t send_pa_end;
	paddr_t recv_pa_begin;
	paddr_t recv_pa_end;

	assert(vm != NULL);
	assert(ppool != NULL);

	if (vm->mailbox.send == NULL || vm->mailbox.recv == NULL) {
		return;
	}

	/* Reset page table entries only for virtual FF-A instances. */
	if (!vm_id_is_current_world(vm->id)) {
		return;
	}

	/* Currently a mailbox size of 1 page is assumed. */
	send_pa_begin = pa_from_va(va_from_ptr(vm->mailbox.send));
	send_pa_end = pa_add(send_pa_begin, HF_MAILBOX_SIZE);
	recv_pa_begin = pa_from_va(va_from_ptr(vm->mailbox.recv));
	recv_pa_end = pa_add(recv_pa_begin, HF_MAILBOX_SIZE);

	mm_stage1_locked = mm_lock_stage1();

	/*
	 * Set the memory region of the buffers back to the default mode
	 * for the VM. Since this memory region was already mapped for
	 * the RXTX buffers we can safely remap them.
	 */
	CHECK(vm_identity_map(vm_locked, send_pa_begin, send_pa_end,
			      MM_MODE_R | MM_MODE_W | MM_MODE_X, ppool, NULL));

	CHECK(vm_identity_map(vm_locked, recv_pa_begin, recv_pa_end,
			      MM_MODE_R | MM_MODE_W | MM_MODE_X, ppool, NULL));

	/* Unmap the buffers in the partition manager. */
	CHECK(mm_unmap(mm_stage1_locked, send_pa_begin, send_pa_end, ppool));
	CHECK(mm_unmap(mm_stage1_locked, recv_pa_begin, recv_pa_end, ppool));

	vm->mailbox.send = NULL;
	vm->mailbox.recv = NULL;

	mm_unlock_stage1(&mm_stage1_locked);
}

void vm_unmap_memory_regions(struct vm_locked vm_locked, struct mpool *ppool)
{
	vm_unmap_rxtx(vm_locked, ppool);

	/* Free all page table entries associated with current VM. */
	vm_free_ptables(vm_locked.vm, ppool);
}

/**
 * Gets the mode of the given range of ipa or va if they are mapped with the
 * same mode.
 *
 * Returns true if the range is mapped with the same mode and false otherwise.
 * The wrapper calls the appropriate mm function depending on if the partition
 * is a vm or a el0 partition.
 */
bool vm_mem_get_mode(struct vm_locked vm_locked, ipaddr_t begin, ipaddr_t end,
		     mm_mode_t *mode)
{
	return arch_vm_mem_get_mode(vm_locked, begin, end, mode);
}

bool vm_iommu_mm_identity_map(struct vm_locked vm_locked, paddr_t begin,
			      paddr_t end, mm_mode_t mode, struct mpool *ppool,
			      ipaddr_t *ipa, uint8_t dma_device_id)
{
	return arch_vm_iommu_mm_identity_map(vm_locked, begin, end, mode, ppool,
					     ipa, dma_device_id);
}

bool vm_mailbox_state_busy(struct vm_locked vm_locked)
{
	return vm_locked.vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	       vm_locked.vm->mailbox.recv == NULL;
}

static struct notifications *vm_get_notifications(struct vm_locked vm_locked,
						  bool is_from_vm)
{
	return is_from_vm ? &vm_locked.vm->notifications.from_vm
			  : &vm_locked.vm->notifications.from_sp;
}

/*
 * Dynamically allocate per_vcpu_notifications structure for a given VM.
 */
static void vm_notifications_init_per_vcpu_notifications(
	struct vm *vm, ffa_vcpu_count_t vcpu_count, struct mpool *ppool)
{
	size_t notif_ppool_entries =
		(align_up(sizeof(struct notifications_state) * vcpu_count,
			  MM_PPOOL_ENTRY_SIZE) /
		 MM_PPOOL_ENTRY_SIZE);

	/*
	 * Allow for function to be called on already initialized VMs but those
	 * that require notification structure to be cleared.
	 */
	if (vm->notifications.from_sp.per_vcpu == NULL) {
		assert(vm->notifications.from_vm.per_vcpu == NULL);
		assert(vcpu_count != 0);
		CHECK(ppool != NULL);
		vm->notifications.from_sp.per_vcpu =
			(struct notifications_state *)mpool_alloc_contiguous(
				ppool, notif_ppool_entries, 1);
		CHECK(vm->notifications.from_sp.per_vcpu != NULL);

		vm->notifications.from_vm.per_vcpu =
			(struct notifications_state *)mpool_alloc_contiguous(
				ppool, notif_ppool_entries, 1);
		CHECK(vm->notifications.from_vm.per_vcpu != NULL);
	} else {
		assert(vm->notifications.from_vm.per_vcpu != NULL);
	}

	memset_s(vm->notifications.from_sp.per_vcpu,
		 sizeof(*(vm->notifications.from_sp.per_vcpu)) * vcpu_count, 0,
		 sizeof(*(vm->notifications.from_sp.per_vcpu)) * vcpu_count);
	memset_s(vm->notifications.from_vm.per_vcpu,
		 sizeof(*(vm->notifications.from_vm.per_vcpu)) * vcpu_count, 0,
		 sizeof(*(vm->notifications.from_vm.per_vcpu)) * vcpu_count);
}

/*
 * Initializes the notifications structure.
 */
static void vm_notifications_init_bindings(struct notifications *notifications)
{
	for (uint32_t i = 0U; i < MAX_FFA_NOTIFICATIONS; i++) {
		notifications->bindings_sender_id[i] = HF_INVALID_VM_ID;
	}
}

/*
 * Initialize notification related structures for a VM.
 */
void vm_notifications_init(struct vm *vm, ffa_vcpu_count_t vcpu_count,
			   struct mpool *ppool)
{
	vm_notifications_init_per_vcpu_notifications(vm, vcpu_count, ppool);

	/* Basic initialization of the notifications structure. */
	vm_notifications_init_bindings(&vm->notifications.from_sp);
	vm_notifications_init_bindings(&vm->notifications.from_vm);
}

void vm_reset_notifications(struct vm_locked vm_locked, struct mpool *ppool)
{
	struct vm *vm = vm_locked.vm;

	/* Clear from_vm notifications. */
	struct notifications *from_vm = &vm->notifications.from_vm;

	/* Clear from_sp notifications. */
	struct notifications *from_sp = &vm->notifications.from_sp;

	size_t notif_ppool_entries =
		(align_up(sizeof(struct notifications_state) * (vm->vcpu_count),
			  MM_PPOOL_ENTRY_SIZE) /
		 MM_PPOOL_ENTRY_SIZE);

	/*
	 * Free the memory allocated to per_vcpu notifications state.
	 * The other fields related to notifications need not be cleared
	 * explicitly here as they will be zeroed during vm reinitialization.
	 */
	mpool_add_chunk(ppool, from_vm->per_vcpu, notif_ppool_entries);
	mpool_add_chunk(ppool, from_sp->per_vcpu, notif_ppool_entries);
}

/**
 * Checks if there are pending notifications.
 */
bool vm_are_notifications_pending(struct vm_locked vm_locked, bool from_vm,
				  ffa_notifications_bitmap_t notifications)
{
	struct notifications *to_check;

	CHECK(vm_locked.vm != NULL);

	to_check = vm_get_notifications(vm_locked, from_vm);

	/* Check if there are pending per vcpu notifications */
	for (uint32_t i = 0U; i < vm_locked.vm->vcpu_count; i++) {
		if ((to_check->per_vcpu[i].pending & notifications) != 0U) {
			return true;
		}
	}

	/* Check if there are global pending notifications */
	return (to_check->global.pending & notifications) != 0U;
}

/**
 * Checks if there are pending global notifications, either from SPs or from
 * VMs.
 */
bool vm_are_global_notifications_pending(struct vm_locked vm_locked)
{
	return vm_get_notifications(vm_locked, true)->global.pending != 0ULL ||
	       vm_get_notifications(vm_locked, false)->global.pending != 0ULL ||
	       vm_are_fwk_notifications_pending(vm_locked);
}

/**
 * Currently only RX full notification is supported as framework notification.
 * Returns true if there is one pending, either from Hypervisor or SPMC.
 */
bool vm_are_fwk_notifications_pending(struct vm_locked vm_locked)
{
	return vm_locked.vm->notifications.framework.pending != 0ULL;
}

/**
 * Checks if there are pending per-vCPU notifications, in a specific vCPU either
 * from SPs or from VMs.
 */
bool vm_are_per_vcpu_notifications_pending(struct vm_locked vm_locked,
					   ffa_vcpu_index_t vcpu_id)
{
	CHECK(vcpu_id < vm_locked.vm->vcpu_count);

	return vm_get_notifications(vm_locked, true)
			       ->per_vcpu[vcpu_id]
			       .pending != 0ULL ||
	       vm_get_notifications(vm_locked, false)
			       ->per_vcpu[vcpu_id]
			       .pending != 0ULL;
}

bool vm_are_notifications_enabled(struct vm *vm)
{
	return vm->notifications.enabled;
}

bool vm_locked_are_notifications_enabled(struct vm_locked vm_locked)
{
	return vm_are_notifications_enabled(vm_locked.vm);
}

static bool vm_is_notification_bit_set(ffa_notifications_bitmap_t notifications,
				       uint32_t i)
{
	return (notifications & FFA_NOTIFICATION_MASK(i)) != 0U;
}

static void vm_notifications_global_state_count_update(
	ffa_notifications_bitmap_t bitmap, uint32_t *counter, int inc)
{
	/*
	 * Helper to increment counters from global notifications
	 * state. Count update by increments or decrements of 1 or -1,
	 * respectively.
	 */
	assert(inc == 1 || inc == -1);

	sl_lock(&all_notifications_state.lock);

	for (uint32_t i = 0; i < MAX_FFA_NOTIFICATIONS; i++) {
		if (vm_is_notification_bit_set(bitmap, i)) {
			CHECK((inc > 0 && *counter < UINT32_MAX) ||
			      (inc < 0 && *counter > 0));
			*counter += inc;
		}
	}

	sl_unlock(&all_notifications_state.lock);
}

/**
 * Helper function to increment the pending notifications based on a bitmap
 * passed as argument.
 * Function to be used at setting notifications for a given VM.
 */
static void vm_notifications_pending_count_add(
	ffa_notifications_bitmap_t to_add)
{
	vm_notifications_global_state_count_update(
		to_add, &all_notifications_state.pending_count, 1);
}

/**
 * Helper function to decrement the pending notifications count.
 * Function to be used when getting the receiver's pending notifications.
 */
static void vm_notifications_pending_count_sub(
	ffa_notifications_bitmap_t to_sub)
{
	vm_notifications_global_state_count_update(
		to_sub, &all_notifications_state.pending_count, -1);
}

/**
 * Helper function to count the notifications whose information has been
 * retrieved by the scheduler of the system, and are still pending.
 */
static void vm_notifications_info_get_retrieved_count_add(
	ffa_notifications_bitmap_t to_add)
{
	vm_notifications_global_state_count_update(
		to_add, &all_notifications_state.info_get_retrieved_count, 1);
}

/**
 * Helper function to subtract the notifications that the receiver is getting
 * and whose information has been retrieved by the receiver scheduler.
 */
static void vm_notifications_info_get_retrieved_count_sub(
	ffa_notifications_bitmap_t to_sub)
{
	vm_notifications_global_state_count_update(
		to_sub, &all_notifications_state.info_get_retrieved_count, -1);
}

/**
 * Helper function to determine if there are notifications pending whose info
 * hasn't been retrieved by the receiver scheduler.
 */
bool vm_notifications_pending_not_retrieved_by_scheduler(void)
{
	bool ret;

	sl_lock(&all_notifications_state.lock);
	ret = all_notifications_state.pending_count >
	      all_notifications_state.info_get_retrieved_count;
	sl_unlock(&all_notifications_state.lock);

	return ret;
}

bool vm_is_notifications_pending_count_zero(void)
{
	bool ret;

	sl_lock(&all_notifications_state.lock);
	ret = all_notifications_state.pending_count == 0;
	sl_unlock(&all_notifications_state.lock);

	return ret;
}

/**
 * Checks that all provided notifications are bound to the specified sender, and
 * are per VCPU or global, as specified.
 */
bool vm_notifications_validate_binding(struct vm_locked vm_locked,
				       bool is_from_vm, ffa_id_t sender_id,
				       ffa_notifications_bitmap_t notifications,
				       bool is_per_vcpu)
{
	return vm_notifications_validate_bound_sender(
		       vm_locked, is_from_vm, sender_id, notifications) &&
	       vm_notifications_validate_per_vcpu(vm_locked, is_from_vm,
						  is_per_vcpu, notifications);
}

/**
 * Update binds information in notification structure for the specified
 * notifications.
 */
void vm_notifications_update_bindings(struct vm_locked vm_locked,
				      bool is_from_vm, ffa_id_t sender_id,
				      ffa_notifications_bitmap_t notifications,
				      bool is_per_vcpu)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_update =
		vm_get_notifications(vm_locked, is_from_vm);

	for (uint32_t i = 0; i < MAX_FFA_NOTIFICATIONS; i++) {
		if (vm_is_notification_bit_set(notifications, i)) {
			to_update->bindings_sender_id[i] = sender_id;
		}
	}

	/*
	 * Set notifications if they are per VCPU, else clear them as they are
	 * global.
	 */
	if (is_per_vcpu) {
		to_update->bindings_per_vcpu |= notifications;
	} else {
		to_update->bindings_per_vcpu &= ~notifications;
	}
}

bool vm_notifications_validate_bound_sender(
	struct vm_locked vm_locked, bool is_from_vm, ffa_id_t sender_id,
	ffa_notifications_bitmap_t notifications)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_check =
		vm_get_notifications(vm_locked, is_from_vm);

	for (uint32_t i = 0; i < MAX_FFA_NOTIFICATIONS; i++) {
		if (vm_is_notification_bit_set(notifications, i) &&
		    to_check->bindings_sender_id[i] != sender_id) {
			return false;
		}
	}

	return true;
}

bool vm_notifications_validate_per_vcpu(struct vm_locked vm_locked,
					bool is_from_vm, bool is_per_vcpu,
					ffa_notifications_bitmap_t notif)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_check =
		vm_get_notifications(vm_locked, is_from_vm);

	return is_per_vcpu ? (~to_check->bindings_per_vcpu & notif) == 0U
			   : (to_check->bindings_per_vcpu & notif) == 0U;
}

static void vm_notifications_state_set(struct notifications_state *state,
				       ffa_notifications_bitmap_t notifications)
{
	/*
	 * Exclude notifications which are already pending, to avoid
	 * leaving the pending counter in a wrongful state.
	 */
	ffa_notifications_bitmap_t to_set =
		(state->pending & notifications) ^ notifications;

	/* Change the state of the pending notifications. */
	state->pending |= to_set;
	vm_notifications_pending_count_add(to_set);
}

void vm_notifications_partition_set_pending(
	struct vm_locked vm_locked, bool is_from_vm,
	ffa_notifications_bitmap_t notifications, ffa_vcpu_index_t vcpu_id,
	bool is_per_vcpu)
{
	struct notifications *to_set;
	struct notifications_state *state;

	CHECK(vm_locked.vm != NULL);
	CHECK(vcpu_id < vm_locked.vm->vcpu_count);

	to_set = vm_get_notifications(vm_locked, is_from_vm);

	state = is_per_vcpu ? &to_set->per_vcpu[vcpu_id] : &to_set->global;

	vm_notifications_state_set(state, notifications);
}

/**
 * Set pending framework notifications.
 */
void vm_notifications_framework_set_pending(
	struct vm_locked vm_locked, ffa_notifications_bitmap_t notifications)
{
	CHECK(vm_locked.vm != NULL);
	assert(is_ffa_spm_buffer_full_notification(notifications) ||
	       is_ffa_hyp_buffer_full_notification(notifications));
	vm_notifications_state_set(&vm_locked.vm->notifications.framework,
				   notifications);
}

static ffa_notifications_bitmap_t vm_notifications_state_get_pending(
	struct notifications_state *state)
{
	ffa_notifications_bitmap_t to_ret;
	ffa_notifications_bitmap_t pending_and_info_get_retrieved;

	assert(state != NULL);

	to_ret = state->pending;

	/* Update count of currently pending notifications in the system. */
	vm_notifications_pending_count_sub(state->pending);

	/*
	 * If notifications receiver is getting have been retrieved by the
	 * receiver scheduler, decrement those from respective count.
	 */
	pending_and_info_get_retrieved =
		state->pending & state->info_get_retrieved;

	if (pending_and_info_get_retrieved != 0) {
		vm_notifications_info_get_retrieved_count_sub(
			pending_and_info_get_retrieved);
	}

	state->pending = 0U;
	state->info_get_retrieved = 0U;

	return to_ret;
}

/**
 * Get global and per-vCPU notifications for the given vCPU ID.
 */
ffa_notifications_bitmap_t vm_notifications_partition_get_pending(
	struct vm_locked vm_locked, bool is_from_vm, ffa_vcpu_index_t vcpu_id)
{
	ffa_notifications_bitmap_t to_ret;
	struct notifications *to_get;

	assert(vm_locked.vm != NULL);
	to_get = vm_get_notifications(vm_locked, is_from_vm);
	assert(vcpu_id < vm_locked.vm->vcpu_count);

	to_ret = vm_notifications_state_get_pending(&to_get->global);
	to_ret |=
		vm_notifications_state_get_pending(&to_get->per_vcpu[vcpu_id]);

	return to_ret;
}

/**
 * Get pending framework notifications.
 */
ffa_notifications_bitmap_t vm_notifications_framework_get_pending(
	struct vm_locked vm_locked)
{
	struct vm *vm = vm_locked.vm;
	ffa_notifications_bitmap_t framework;

	assert(vm != NULL);

	framework = vm_notifications_state_get_pending(
		&vm->notifications.framework);

	return framework;
}

static bool vm_insert_notification_info_list(
	ffa_id_t vm_id, bool is_per_vcpu, ffa_vcpu_index_t vcpu_id,
	uint16_t *ids, uint32_t *ids_count, uint32_t *lists_sizes,
	uint32_t *lists_count, const uint32_t ids_max_count,
	enum notifications_info_get_state *info_get_state)
{
	CHECK(*ids_count <= ids_max_count);
	CHECK(*lists_count <= ids_max_count);

	if (*info_get_state == FULL || *ids_count == ids_max_count) {
		*info_get_state = FULL;
		return false;
	}

	switch (*info_get_state) {
	case INIT:
	case STARTING_NEW:
		/*
		 * At this iteration two ids are to be added: the VM ID
		 * and vCPU ID. If there is no space, change state and
		 * terminate function.
		 */
		if (is_per_vcpu && ids_max_count - *ids_count < 2) {
			*info_get_state = FULL;
			return false;
		}

		*info_get_state = INSERTING;
		ids[*ids_count] = vm_id;
		++(*ids_count);

		if (is_per_vcpu) {
			/* Insert vCPU ID. */
			ids[*ids_count] = vcpu_id;
			++(*ids_count);
			++lists_sizes[*lists_count];
		}

		++(*lists_count);
		break;
	case INSERTING:
		/* For per-vCPU notifications only. */
		if (!is_per_vcpu) {
			break;
		}

		/* Insert vCPU ID */
		ids[*ids_count] = vcpu_id;
		(*ids_count)++;
		/* Increment respective list size */
		++lists_sizes[*lists_count - 1];

		if (lists_sizes[*lists_count - 1] == 3) {
			*info_get_state = STARTING_NEW;
		}
		break;
	default:
		panic("Notification info get action error!!\n");
	}

	return true;
}

/**
 * Check if the notification is pending and hasn't being retrieved.
 * If so attempt to add it to the notification info list.
 * Returns true if successfully added to the list.
 */
static bool vm_notifications_state_info_get(
	struct notifications_state *state, ffa_id_t vm_id, bool is_per_vcpu,
	ffa_vcpu_index_t vcpu_id, uint16_t *ids, uint32_t *ids_count,
	uint32_t *lists_sizes, uint32_t *lists_count,
	const uint32_t ids_max_count,
	enum notifications_info_get_state *info_get_state)
{
	ffa_notifications_bitmap_t pending_not_retrieved;

	pending_not_retrieved = state->pending & ~state->info_get_retrieved;

	/* No notifications pending that haven't been retrieved. */
	if (pending_not_retrieved == 0U) {
		return false;
	}

	if (!vm_insert_notification_info_list(
		    vm_id, is_per_vcpu, vcpu_id, ids, ids_count, lists_sizes,
		    lists_count, ids_max_count, info_get_state)) {
		return false;
	}

	state->info_get_retrieved |= pending_not_retrieved;

	vm_notifications_info_get_retrieved_count_add(pending_not_retrieved);

	return true;
}

/**
 * Insert partition information and vCPU ID in the return to notification
 * information, if the vCPU has pending interrupts that need explicit CPU
 * cycles from the scheduler to the partition.
 *
 * This can be if:
 * - Partition has configured in the partition manifest an SRI policy, and
 *   it is in the waiting state.
 * - If it has pending IPIs, and it is in the waiting state.
 *
 * Returns true if successfully added to the list.
 */
static void vm_interrupts_info_get(
	struct vcpu *vcpu, ffa_id_t vm_id, ffa_vcpu_index_t vcpu_id,
	uint16_t *ids, uint32_t *ids_count, uint32_t *lists_sizes,
	uint32_t *lists_count, const uint32_t ids_max_count,
	enum notifications_info_get_state *info_get_state, bool per_vcpu_added)

{
	struct vcpu_locked vcpu_locked = vcpu_lock(vcpu);
	struct vm *vm = vcpu->vm;
	bool sri_interrupts_policy_configured =
		vm->sri_policy.intr_while_waiting ||
		vm->sri_policy.intr_pending_entry_wait;

	/*
	 * If the information about interrupts in the current vCPU has been
	 * retrieved or there are no pending interrupts, skip inserting an
	 * element in the list.
	 */
	if (vcpu->interrupts_info_get_retrieved ||
	    vcpu_virt_interrupt_count_get(vcpu_locked) == 0U) {
		goto out;
	}

	/*
	 * Report for any interrupt that is pending if partition is in the
	 * waiting state, and either:
	 * - The target partition is configured with an SRI policy.
	 * - There are pending IPI and the SP in the waiting state.
	 */
	if (vcpu->state == VCPU_STATE_WAITING &&
	    (sri_interrupts_policy_configured ||
	     vcpu_is_virt_interrupt_pending(&vcpu->interrupts, HF_IPI_INTID))) {
		if (per_vcpu_added ||
		    vm_insert_notification_info_list(
			    vm_id, true, vcpu_id, ids, ids_count, lists_sizes,
			    lists_count, ids_max_count, info_get_state)) {
			vcpu->interrupts_info_get_retrieved = true;
		}
	}
out:
	vcpu_unlock(&vcpu_locked);
}

/**
 * Get pending notification's information to return to the receiver scheduler.
 */
void vm_notifications_info_get_pending(
	struct vm_locked vm_locked, bool is_from_vm, uint16_t *ids,
	uint32_t *ids_count, uint32_t *lists_sizes, uint32_t *lists_count,
	const uint32_t ids_max_count,
	enum notifications_info_get_state *info_get_state)
{
	struct notifications *notifications;

	CHECK(vm_locked.vm != NULL);

	notifications = vm_get_notifications(vm_locked, is_from_vm);

	/*
	 * Perform info get for global notifications, before doing it for
	 * per-vCPU.
	 */
	vm_notifications_state_info_get(&notifications->global,
					vm_locked.vm->id, false, 0, ids,
					ids_count, lists_sizes, lists_count,
					ids_max_count, info_get_state);

	for (ffa_vcpu_count_t i = 0; i < vm_locked.vm->vcpu_count; i++) {
		struct vcpu *vcpu = vm_get_vcpu(vm_locked.vm, i);
		bool per_vcpu_added;

		per_vcpu_added = vm_notifications_state_info_get(
			&notifications->per_vcpu[i], vm_locked.vm->id, true, i,
			ids, ids_count, lists_sizes, lists_count, ids_max_count,
			info_get_state);
		/*
		 * IPIs can only be pending for partitions at the
		 * current virtual FF-A instance.
		 */
		if (vm_id_is_current_world(vm_locked.vm->id)) {
			vm_interrupts_info_get(vcpu, vm_locked.vm->id, i, ids,
					       ids_count, lists_sizes,
					       lists_count, ids_max_count,
					       info_get_state, per_vcpu_added);
		}
	}
}

/**
 * Gets all info from VM's pending notifications.
 * Returns true if the list is full, and there is more pending.
 */
bool vm_notifications_info_get(struct vm_locked vm_locked, uint16_t *ids,
			       uint32_t *ids_count, uint32_t *lists_sizes,
			       uint32_t *lists_count,
			       const uint32_t ids_max_count)
{
	enum notifications_info_get_state current_state = INIT;

	/* Get info of pending notifications from the framework. */
	vm_notifications_state_info_get(&vm_locked.vm->notifications.framework,
					vm_locked.vm->id, false, 0, ids,
					ids_count, lists_sizes, lists_count,
					ids_max_count, &current_state);

	/* Get info of pending notifications from SPs. */
	vm_notifications_info_get_pending(vm_locked, false, ids, ids_count,
					  lists_sizes, lists_count,
					  ids_max_count, &current_state);

	/* Get info of pending notifications from VMs. */
	vm_notifications_info_get_pending(vm_locked, true, ids, ids_count,
					  lists_sizes, lists_count,
					  ids_max_count, &current_state);

	/*
	 * State transitions to FULL when trying to insert a new ID in the
	 * list and there is not more space. This means there are
	 * notifications pending, whose info is not retrieved.
	 */
	return current_state == FULL;
}

/**
 * Checks VM's messaging method support.
 */
bool vm_supports_messaging_method(struct vm *vm, uint16_t messaging_method)
{
	return (vm->messaging_method & messaging_method) != 0;
}

/**
 * Sets the designated GP register that the VM expects to receive the boot
 * info's address.
 */
void vm_set_boot_info_gp_reg(struct vm *vm, struct vcpu *vcpu)
{
	if (vm->boot_info.blob_addr.ipa != 0U) {
		arch_regs_set_gp_reg(&vcpu->regs,
				     ipa_addr(vm->boot_info.blob_addr),
				     vm->boot_info.gp_register_num);
	}
}

/**
 * Obtain the interrupt descriptor entry of the specified vm corresponding
 * to the specific interrupt id.
 */
static struct interrupt_descriptor *vm_find_interrupt_descriptor(
	struct vm_locked vm_locked, uint32_t id)
{
	for (uint32_t i = 0; i < VM_MANIFEST_MAX_INTERRUPTS; i++) {
		/* Interrupt descriptors are populated contiguously. */
		if (!vm_locked.vm->interrupt_desc[i].valid) {
			break;
		}

		if (vm_locked.vm->interrupt_desc[i].interrupt_id == id) {
			/* Interrupt descriptor found. */
			return &vm_locked.vm->interrupt_desc[i];
		}
	}

	return NULL;
}

/**
 * Update the target MPIDR corresponding to the specified interrupt id
 * belonging to the specified vm.
 */
struct interrupt_descriptor *vm_interrupt_set_target_mpidr(
	struct vm_locked vm_locked, uint32_t id, uint32_t target_mpidr)
{
	struct interrupt_descriptor *int_desc;

	int_desc = vm_find_interrupt_descriptor(vm_locked, id);

	if (int_desc != NULL) {
		int_desc->mpidr_valid = true;
		int_desc->mpidr = target_mpidr;
	}

	return int_desc;
}

/**
 * Update the security state of the specified interrupt id belonging to the
 * specified vm.
 */
struct interrupt_descriptor *vm_interrupt_set_sec_state(
	struct vm_locked vm_locked, uint32_t id, uint32_t sec_state)
{
	struct interrupt_descriptor *int_desc;

	int_desc = vm_find_interrupt_descriptor(vm_locked, id);

	if (int_desc != NULL) {
		int_desc->sec_state = sec_state;
	}

	return int_desc;
}

/**
 * Enable or disable the specified interrupt id belonging to specified vm.
 */
struct interrupt_descriptor *vm_interrupt_set_enable(struct vm_locked vm_locked,
						     uint32_t id, bool enable)
{
	struct interrupt_descriptor *int_desc;

	int_desc = vm_find_interrupt_descriptor(vm_locked, id);

	if (int_desc != NULL) {
		int_desc->enabled = enable;
	}

	return int_desc;
}

/**
 * The 'boot_list' is used as the start and end of the list.
 * Start: the nodes it points to is the first VM to boot.
 * End: the last node's next points to the entry.
 */
static bool vm_is_boot_list_end(struct vm *vm)
{
	return vm->boot_list_node.next == &boot_list;
}

/**
 * Gets the first partition to boot, according to Boot Protocol from FF-A spec.
 */
struct vm *vm_get_boot_vm(void)
{
	assert(!list_empty(&boot_list));

	return CONTAINER_OF(boot_list.next, struct vm, boot_list_node);
}

/**
 * Gets the first MP partition to boot on a secondary CPU, as per the boot
 * order from FF-A spec.
 * If every SP in the system is an UP partition, this function returns NULL.
 */
struct vm *vm_get_boot_vm_secondary_core(void)
{
	struct vm *vm = vm_get_boot_vm();

	if (vm_is_up(vm)) {
		return vm_get_next_boot_secondary_core(vm);
	}

	return vm;
}

/**
 * Returns the next element in the boot order list, if there is one.
 */
struct vm *vm_get_next_boot(struct vm *vm)
{
	return vm_is_boot_list_end(vm)
		       ? NULL
		       : CONTAINER_OF(vm->boot_list_node.next, struct vm,
				      boot_list_node);
}

/**
 * Returns the next element representing an MP endpoint in the boot order list,
 * if there is one.
 */
struct vm *vm_get_next_boot_secondary_core(struct vm *vm)
{
	struct vm *vm_next;

	assert(vm != NULL);

	vm_next = vm_get_next_boot(vm);

	/* Keep searching until an MP endpoint is found. */
	while (vm_next != NULL && vm_is_up(vm_next)) {
		vm_next = vm_get_next_boot(vm_next);
	}

	return vm_next;
}

/**
 * Insert in boot list, sorted by `boot_order` parameter in the vm structure
 * and rooted in `first_boot_vm`.
 */
void vm_update_boot(struct vm *vm)
{
	struct vm *current_vm = NULL;

	if (list_empty(&boot_list)) {
		list_prepend(&boot_list, &vm->boot_list_node);
		return;
	}

	/*
	 * When getting to this point the first insertion should have
	 * been done.
	 */
	current_vm = vm_get_boot_vm();
	assert(current_vm != NULL);

	/*
	 * Iterate until the position is found according to boot order, or
	 * until we reach end of the list.
	 */
	while (!vm_is_boot_list_end(current_vm) &&
	       current_vm->boot_order <= vm->boot_order) {
		current_vm = vm_get_next_boot(current_vm);
	}

	current_vm->boot_order > vm->boot_order
		? list_prepend(&current_vm->boot_list_node, &vm->boot_list_node)
		: list_append(&current_vm->boot_list_node, &vm->boot_list_node);
}

/**
 * Light weight read operation. Its safe to access the state without a lock.
 * The atomic primitive ensures any update by another CPU to this field is
 * visible.
 */
enum vm_state vm_read_state(struct vm *vm)
{
	return __atomic_load_n(&vm->state, __ATOMIC_ACQUIRE);
}

/* Internal helper. Not safe to write to the state field without a lock. */
static void vm_write_state(struct vm *vm, enum vm_state new_state)
{
	__atomic_store_n(&vm->state, new_state, __ATOMIC_RELEASE);
}

static inline const char *vm_state_print_name(enum vm_state state)
{
	switch (state) {
	case VM_STATE_NULL:
		return "VM_STATE_NULL";
	case VM_STATE_CREATED:
		return "VM_STATE_CREATED";
	case VM_STATE_RUNNING:
		return "VM_STATE_RUNNING";
	case VM_STATE_ABORTING:
		return "VM_STATE_ABORTING";
	}
}

/**
 * Perform legal transitions between various states of a VM. The caller is
 * expected to hold the VM's lock.
 *
 * The following state transitions are valid:
 * NULL     -> CREATED   : Hafnium successfully initialized the VM.
 * CREATED  -> RUNNING   : The first execution context has been allocated CPU
 *                         cycles.
 * RUNNING  -> ABORTING  : An execution context of VM encountered fatal error.
 * ABORTING -> NULL      : Hafnium destroyed the VM.
 * ABORTING -> CREATED   : Hafnium has reinitialized the VM with the aim of
 *                         restarting it.
 *
 * Return true if the transition is valid and the state was updated, false
 * otherwise.
 */
bool vm_set_state(struct vm_locked vm_locked, enum vm_state to_state)
{
	struct vm *vm = vm_locked.vm;
	enum vm_state from_state;
	bool ret = false;

	assert(vm != NULL);
	from_state = vm_read_state(vm);

	if (to_state == from_state) {
		return true;
	}

	switch (from_state) {
	case VM_STATE_NULL:
		if (to_state == VM_STATE_CREATED) {
			ret = true;
		}
		break;
	case VM_STATE_CREATED:
		if (to_state == VM_STATE_RUNNING ||
		    to_state == VM_STATE_ABORTING) {
			ret = true;
		}
		break;
	case VM_STATE_RUNNING:
		if (to_state == VM_STATE_ABORTING) {
			ret = true;
		}
		break;
	case VM_STATE_ABORTING:
		if (to_state == VM_STATE_NULL || to_state == VM_STATE_CREATED) {
			ret = true;
		}
		break;
	default:
		ret = false;
		break;
	}

	if (ret) {
		vm_write_state(vm, to_state);
	} else {
		dlog_error("Partition %#x transition from %s to %s failed.\n",
			   vm->id, vm_state_print_name(vm->state),
			   vm_state_print_name(to_state));
	}

	return ret;
}

/**
 * If a VM is not in NULL state, then it is discoverable.
 */
bool vm_is_discoverable(struct vm *vm)
{
	return vm_read_state(vm) != VM_STATE_NULL;
}

bool vm_get_range_by_mode(struct vm_locked vm_locked, uintptr_t *begin,
			  uintptr_t *end, mm_mode_t mode, uintptr_t *start_addr,
			  mm_mode_t *ptable_mode)
{
	return arch_vm_get_range_by_mode(vm_locked, begin, end, mode,
					 start_addr, ptable_mode);
}
