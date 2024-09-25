/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/vcpu.h"

#include "hf/arch/cpu.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/std.h"
#include "hf/vm.h"

static struct list_entry boot_list = LIST_INIT(boot_list);

/** GP register to be used to pass the current vCPU ID, at core bring up. */
#define PHYS_CORE_IDX_GP_REG 4

/**
 * Locks the given vCPU and updates `locked` to hold the newly locked vCPU.
 */
struct vcpu_locked vcpu_lock(struct vcpu *vcpu)
{
	struct vcpu_locked locked = {
		.vcpu = vcpu,
	};

	sl_lock(&vcpu->lock);

	return locked;
}

/**
 * Locks two vCPUs ensuring that the locking order is according to the locks'
 * addresses.
 */
struct two_vcpu_locked vcpu_lock_both(struct vcpu *vcpu1, struct vcpu *vcpu2)
{
	struct two_vcpu_locked dual_lock;

	sl_lock_both(&vcpu1->lock, &vcpu2->lock);
	dual_lock.vcpu1.vcpu = vcpu1;
	dual_lock.vcpu2.vcpu = vcpu2;

	return dual_lock;
}

/**
 * Unlocks a vCPU previously locked with vpu_lock, and updates `locked` to
 * reflect the fact that the vCPU is no longer locked.
 */
void vcpu_unlock(struct vcpu_locked *locked)
{
	sl_unlock(&locked->vcpu->lock);
	locked->vcpu = NULL;
}

void vcpu_init(struct vcpu *vcpu, struct vm *vm)
{
	memset_s(vcpu, sizeof(*vcpu), 0, sizeof(*vcpu));
	sl_init(&vcpu->lock);
	vcpu->regs_available = true;
	vcpu->vm = vm;
	vcpu->state = VCPU_STATE_OFF;
	vcpu->direct_request_origin.is_ffa_req2 = false;
	vcpu->direct_request_origin.vm_id = HF_INVALID_VM_ID;
	vcpu->rt_model = RTM_SP_INIT;
	list_init(&vcpu->boot_list_node);
	list_init(&vcpu->timer_node);
}

/**
 * Initialise the registers for the given vCPU and set the state to
 * VCPU_STATE_WAITING. The caller must hold the vCPU lock while calling this.
 */
void vcpu_on(struct vcpu_locked vcpu, ipaddr_t entry, uintreg_t arg)
{
	arch_regs_set_pc_arg(&vcpu.vcpu->regs, entry, arg);
	vcpu.vcpu->state = VCPU_STATE_WAITING;
}

ffa_vcpu_index_t vcpu_index(const struct vcpu *vcpu)
{
	size_t index = vcpu - vcpu->vm->vcpus;

	CHECK(index < UINT16_MAX);
	return index;
}

/**
 * Check whether the given vcpu_state is an off state, for the purpose of
 * turning vCPUs on and off. Note that Aborted still counts as ON for the
 * purposes of PSCI, because according to the PSCI specification (section
 * 5.7.1) a core is only considered to be off if it has been turned off
 * with a CPU_OFF call or hasn't yet been turned on with a CPU_ON call.
 */
bool vcpu_is_off(struct vcpu_locked vcpu)
{
	return (vcpu.vcpu->state == VCPU_STATE_OFF);
}

/**
 * Starts a vCPU of a secondary VM.
 *
 * Returns true if the secondary was reset and started, or false if it was
 * already on and so nothing was done.
 */
bool vcpu_secondary_reset_and_start(struct vcpu_locked vcpu_locked,
				    ipaddr_t entry, uintreg_t arg)
{
	struct vm *vm = vcpu_locked.vcpu->vm;
	bool vcpu_was_off;

	CHECK(vm->id != HF_PRIMARY_VM_ID);

	vcpu_was_off = vcpu_is_off(vcpu_locked);
	if (vcpu_was_off) {
		/*
		 * Set vCPU registers to a clean state ready for boot. As this
		 * is a secondary which can migrate between pCPUs, the ID of the
		 * vCPU is defined as the index and does not match the ID of the
		 * pCPU it is running on.
		 */
		arch_regs_reset(vcpu_locked.vcpu);
		vcpu_on(vcpu_locked, entry, arg);
	}

	return vcpu_was_off;
}

/**
 * Handles a page fault. It does so by determining if it's a legitimate or
 * spurious fault, and recovering from the latter.
 *
 * Returns true if the caller should resume the current vCPU, or false if its VM
 * should be aborted.
 */
bool vcpu_handle_page_fault(const struct vcpu *current,
			    struct vcpu_fault_info *f)
{
	struct vm *vm = current->vm;
	uint32_t mode;
	uint32_t mask = f->mode | MM_MODE_INVALID;
	bool resume;
	struct vm_locked locked_vm;

	locked_vm = vm_lock(vm);
	/*
	 * Check if this is a legitimate fault, i.e., if the page table doesn't
	 * allow the access attempted by the VM.
	 *
	 * Otherwise, this is a spurious fault, likely because another CPU is
	 * updating the page table. It is responsible for issuing global TLB
	 * invalidations while holding the VM lock, so we don't need to do
	 * anything else to recover from it. (Acquiring/releasing the lock
	 * ensured that the invalidations have completed.)
	 */
	if (!locked_vm.vm->el0_partition) {
		resume = vm_mem_get_mode(locked_vm, f->ipaddr,
					 ipa_add(f->ipaddr, 1), &mode) &&
			 (mode & mask) == f->mode;
	} else {
		/*
		 * For EL0 partitions we need to get the mode for the faulting
		 * vaddr.
		 */
		resume =
			vm_mem_get_mode(locked_vm, ipa_init(va_addr(f->vaddr)),
					ipa_add(ipa_init(va_addr(f->vaddr)), 1),
					&mode) &&
			(mode & mask) == f->mode;

		/*
		 * For EL0 partitions, if there is an instruction abort and the
		 * mode of the page is RWX, we don't resume since Hafnium does
		 * not allow write and executable pages.
		 */
		if ((f->mode == MM_MODE_X) &&
		    ((mode & MM_MODE_W) == MM_MODE_W)) {
			resume = false;
		}
	}

	vm_unlock(&locked_vm);

	if (!resume) {
		dlog_warning(
			"Stage-%d page fault: pc=%#lx, vmid=%#x, vcpu=%u, "
			"vaddr=%#lx, ipaddr=%#lx, mode=%#x %#x\n",
			current->vm->el0_partition ? 1 : 2, va_addr(f->pc),
			vm->id, vcpu_index(current), va_addr(f->vaddr),
			ipa_addr(f->ipaddr), f->mode, mode);
	}

	return resume;
}

void vcpu_set_phys_core_idx(struct vcpu *vcpu)
{
	arch_regs_set_gp_reg(&vcpu->regs, cpu_index(vcpu->cpu),
			     PHYS_CORE_IDX_GP_REG);
}

/**
 * Sets the designated GP register through which the vCPU expects to receive the
 * boot info's address.
 */
void vcpu_set_boot_info_gp_reg(struct vcpu *vcpu)
{
	struct vm *vm = vcpu->vm;
	uint32_t gp_register_num = vm->boot_info.gp_register_num;

	if (vm->boot_info.blob_addr.ipa != 0U) {
		arch_regs_set_gp_reg(&vcpu->regs,
				     ipa_addr(vm->boot_info.blob_addr),
				     gp_register_num);
	}
}

/**
 * The 'boot_list' is used as the start and end of the list.
 * Start: the nodes it points to is the first vCPU to boot.
 * End: the last node's next points to the entry.
 */
static bool vcpu_is_boot_list_end(struct vcpu *vcpu)
{
	return vcpu->boot_list_node.next == &boot_list;
}

/**
 * Gets the first partition to boot, according to Boot Protocol from FFA spec.
 */
struct vcpu *vcpu_get_boot_vcpu(void)
{
	assert(!list_empty(&boot_list));

	return CONTAINER_OF(boot_list.next, struct vcpu, boot_list_node);
}

/**
 * Returns the next element in the boot order list, if there is one.
 */
struct vcpu *vcpu_get_next_boot(struct vcpu *vcpu)
{
	return vcpu_is_boot_list_end(vcpu)
		       ? NULL
		       : CONTAINER_OF(vcpu->boot_list_node.next, struct vcpu,
				      boot_list_node);
}

/**
 * Insert in boot list, sorted by `boot_order` parameter in the vm structure
 * and rooted in `first_boot_vm`.
 */
void vcpu_update_boot(struct vcpu *vcpu)
{
	struct vcpu *current = NULL;

	if (list_empty(&boot_list)) {
		list_prepend(&boot_list, &vcpu->boot_list_node);
		return;
	}

	/*
	 * When getting to this point the first insertion should have
	 * been done.
	 */
	current = vcpu_get_boot_vcpu();
	assert(current != NULL);

	/*
	 * Iterate until the position is found according to boot order, or
	 * until we reach end of the list.
	 */
	while (!vcpu_is_boot_list_end(current) &&
	       current->vm->boot_order <= vcpu->vm->boot_order) {
		current = vcpu_get_next_boot(current);
	}

	current->vm->boot_order > vcpu->vm->boot_order
		? list_prepend(&current->boot_list_node, &vcpu->boot_list_node)
		: list_append(&current->boot_list_node, &vcpu->boot_list_node);
}

void vcpu_interrupt_clear_decrement(struct vcpu_locked vcpu_locked,
				    uint32_t intid)
{
	struct interrupts *interrupts = &(vcpu_locked.vcpu->interrupts);

	/* Clear any specifics for the current intid. */
	switch (intid) {
	case HF_IPI_INTID:
		vcpu_ipi_clear_info_get_retrieved(vcpu_locked);
		break;
	default:
		/* Do no additional work. */
		break;
	}

	vcpu_virt_interrupt_clear_pending(interrupts, intid);
	vcpu_interrupt_count_decrement(vcpu_locked, interrupts, intid);
}

/**
 * Sets the vcpu in the VCPU_STATE_RUNNING.
 * With that, its register are set as "not available".
 * If there are registers to be written to vCPU's context, do so.
 * However, this action is restricted to WAITING and BLOCKED states,
 * as such, assert accordingly.
 */
void vcpu_set_running(struct vcpu_locked target_locked,
		      const struct ffa_value *args)
{
	struct vcpu *target_vcpu = target_locked.vcpu;

	if (args != NULL) {
		CHECK(target_vcpu->regs_available);
		assert(target_vcpu->state == VCPU_STATE_WAITING ||
		       target_vcpu->state == VCPU_STATE_BLOCKED);

		arch_regs_set_retval(&target_vcpu->regs, *args);
	}

	/* Mark the registers as unavailable now. */
	target_vcpu->regs_available = false;

	/* We are about to resume target vCPU. */
	target_vcpu->state = VCPU_STATE_RUNNING;
}

/**
 * It injects a virtual interrupt in the vcpu if is enabled and is not pending.
 */
void vcpu_interrupt_inject(struct vcpu_locked target_locked, uint32_t intid)
{
	struct vcpu *target_vcpu = target_locked.vcpu;
	struct interrupts *interrupts = &target_vcpu->interrupts;

	/*
	 * We only need to change state and (maybe) trigger a virtual interrupt
	 * if it is enabled and was not previously pending. Otherwise we can
	 * skip everything except setting the pending bit.
	 */
	if (!(vcpu_is_virt_interrupt_enabled(interrupts, intid) &&
	      !vcpu_is_virt_interrupt_pending(interrupts, intid))) {
		goto out;
	}

	/* Increment the count. */
	vcpu_interrupt_count_increment(target_locked, interrupts, intid);

	/*
	 * Only need to update state if there was not already an
	 * interrupt enabled and pending.
	 */
	if (vcpu_interrupt_count_get(target_locked) != 1) {
		goto out;
	}

out:
	/* Either way, make it pending. */
	vcpu_virt_interrupt_set_pending(interrupts, intid);
}

void vcpu_enter_secure_interrupt_rtm(struct vcpu_locked vcpu_locked)
{
	struct vcpu *target_vcpu = vcpu_locked.vcpu;

	assert(target_vcpu->scheduling_mode == NONE);
	assert(target_vcpu->call_chain.prev_node == NULL);
	assert(target_vcpu->call_chain.next_node == NULL);
	assert(target_vcpu->rt_model == RTM_NONE);

	target_vcpu->scheduling_mode = SPMC_MODE;
	target_vcpu->rt_model = RTM_SEC_INTERRUPT;
}

static uint16_t queue_increment_index(uint16_t current_idx)
{
	/* Look at the next index. Wrap around if necessary. */
	if (current_idx == VINT_QUEUE_MAX - 1) {
		return 0;
	}

	return current_idx + 1;
}

static bool is_queue_empty(struct interrupt_queue *q)
{
	if (q->head == q->tail) {
		return true;
	}

	return false;
}

/**
 * Queue the pending virtual interrupt for target vCPU.
 *
 * Returns true if successful in pushing a new entry to the queue, or false
 * otherwise.
 */
bool vcpu_interrupt_queue_push(struct vcpu_locked vcpu_locked, uint32_t vint_id)
{
	struct interrupt_queue *q;
	uint16_t new_tail;

	assert(vint_id != HF_INVALID_INTID);

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	/*
	 * A new entry is pushed at the tail of the queue. Upon successful
	 * push operation, the tail increments or wraps around.
	 */
	new_tail = queue_increment_index(q->tail);

	/* If new_tail reaches head of the queue, then the queue is full. */
	if (new_tail == q->head) {
		return false;
	}

	/* Add the virtual interrupt to the queue. */
	q->vint_buffer[q->tail] = vint_id;
	q->tail = new_tail;

	return true;
}

/**
 * Remove an entry from the specified vCPU's queue at the head.
 *
 * Returns true if successful in removing the entry, or false otherwise.
 */
bool vcpu_interrupt_queue_pop(struct vcpu_locked vcpu_locked, uint32_t *vint_id)
{
	struct interrupt_queue *q;
	uint16_t new_head;

	assert(vint_id != NULL);

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	/* Check if queue is empty. */
	if (is_queue_empty(q)) {
		return false;
	}

	/*
	 * An entry is removed from the head of the queue. Once successful, the
	 * head is incremented or wrapped around if needed.
	 */
	new_head = queue_increment_index(q->head);
	*vint_id = q->vint_buffer[q->head];
	q->head = new_head;

	return true;
}

/**
 * Look for the first pending virtual interrupt from the vcpu's queue. Note
 * that the entry is not removed from the queue.
 *
 * Returns true if a valid entry exists in the queue, or false otherwise.
 */
bool vcpu_interrupt_queue_peek(struct vcpu_locked vcpu_locked,
			       uint32_t *vint_id)
{
	struct interrupt_queue *q;
	uint32_t queued_vint;

	assert(vint_id != NULL);

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	/* Check if queue is empty. */
	if (is_queue_empty(q)) {
		return false;
	}

	queued_vint = q->vint_buffer[q->head];
	assert(queued_vint != HF_INVALID_INTID);

	*vint_id = queued_vint;
	return true;
}

/**
 * Find if a specific virtual interrupt exists in the specified vCPU's queue.
 *
 * Returns true if such an entry exists in the queue, or false otherwise.
 */
bool vcpu_is_interrupt_in_queue(struct vcpu_locked vcpu_locked,
				uint32_t vint_id)
{
	struct interrupt_queue *q;
	uint16_t next;

	assert(vint_id != HF_INVALID_INTID);

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	/* Check if the queue is empty. */
	if (is_queue_empty(q)) {
		return false;
	}

	next = q->head;
	while (true) {
		/* Match found. */
		if (q->vint_buffer[next] == vint_id) {
			return true;
		}

		next = queue_increment_index(next);

		/* Reached the end of queue. */
		if (next == q->tail) {
			break;
		}
	}

	return false;
}

/**
 * Check if there are any entries in the interrupt queue.
 *
 * Returns true if queue is empty, or false otherwise.
 */
bool vcpu_is_interrupt_queue_empty(struct vcpu_locked vcpu_locked)
{
	struct interrupt_queue *q;

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	if (is_queue_empty(q)) {
		return true;
	}

	return false;
}

/**
 * When interrupt handling is complete the preempted_vcpu field should go back
 * to NULL.
 */
void vcpu_secure_interrupt_complete(struct vcpu_locked vcpu_locked)
{
	struct vcpu *vcpu;

	vcpu = vcpu_locked.vcpu;
	vcpu->preempted_vcpu = NULL;
	vcpu->requires_deactivate_call = false;
}
