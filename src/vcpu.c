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
	list_init(&vcpu->timer_node);
	list_init(&vcpu->ipi_list_node);
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
	mm_mode_t mode;
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

static bool vcpu_is_virt_interrupt_enabled(struct interrupts *interrupts,
					   uint32_t intid)
{
	return interrupt_bitmap_get_value(&interrupts->interrupt_enabled,
					  intid) == 1U;
}

static void vcpu_virt_interrupt_set_enabled(struct interrupts *interrupts,
					    uint32_t intid)
{
	interrupt_bitmap_set_value(&interrupts->interrupt_enabled, intid);
}

static void vcpu_virt_interrupt_clear_enabled(struct interrupts *interrupts,
					      uint32_t intid)
{
	interrupt_bitmap_clear_value(&interrupts->interrupt_enabled, intid);
}

static void vcpu_virt_interrupt_set_pending(struct interrupts *interrupts,
					    uint32_t intid)
{
	interrupt_bitmap_set_value(&interrupts->interrupt_pending, intid);
}

static void vcpu_virt_interrupt_clear_pending(struct interrupts *interrupts,
					      uint32_t intid)
{
	interrupt_bitmap_clear_value(&interrupts->interrupt_pending, intid);
}

static void vcpu_irq_count_increment(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count++;
}

static void vcpu_irq_count_decrement(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count--;
}

static void vcpu_fiq_count_increment(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count++;
}

static void vcpu_fiq_count_decrement(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count--;
}

static void vcpu_interrupt_count_increment(struct vcpu_locked vcpu_locked,
					   uint32_t intid)
{
	struct interrupts *interrupts = &vcpu_locked.vcpu->interrupts;

	if (vcpu_virt_interrupt_get_type(interrupts, intid) ==
	    INTERRUPT_TYPE_IRQ) {
		vcpu_irq_count_increment(vcpu_locked);
	} else {
		vcpu_fiq_count_increment(vcpu_locked);
	}
}

static void vcpu_interrupt_count_decrement(struct vcpu_locked vcpu_locked,
					   uint32_t intid)
{
	struct interrupts *interrupts = &vcpu_locked.vcpu->interrupts;

	if (vcpu_virt_interrupt_get_type(interrupts, intid) ==
	    INTERRUPT_TYPE_IRQ) {
		vcpu_irq_count_decrement(vcpu_locked);
	} else {
		vcpu_fiq_count_decrement(vcpu_locked);
	}
}

uint32_t vcpu_virt_interrupt_irq_count_get(struct vcpu_locked vcpu_locked)
{
	return vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count;
}

uint32_t vcpu_virt_interrupt_fiq_count_get(struct vcpu_locked vcpu_locked)
{
	return vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count;
}

uint32_t vcpu_virt_interrupt_count_get(struct vcpu_locked vcpu_locked)
{
	return vcpu_virt_interrupt_irq_count_get(vcpu_locked) +
	       vcpu_virt_interrupt_fiq_count_get(vcpu_locked);
}

static void vcpu_interrupt_clear_decrement(struct vcpu_locked vcpu_locked,
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

	/*
	 * Mark the virtual interrupt as no longer pending and decrement
	 * the interrupt count if it is enabled.
	 */
	vcpu_virt_interrupt_clear_pending(interrupts, intid);
	if (vcpu_is_virt_interrupt_enabled(interrupts, intid)) {
		vcpu_interrupt_count_decrement(vcpu_locked, intid);
	}
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

/**
 * If tail reaches head of the queue, and the count of queued interrupts
 * 0, then the queue is empty.
 */
static bool is_queue_empty(struct interrupt_queue *q)
{
	return q->head == q->tail && q->queued_vint_count == 0U;
}

/**
 * If tail reaches head of the queue, and the count of queued interrupts
 * matches the size of the buffer, then the queue is full.
 */
static bool is_queue_full(struct interrupt_queue *q)
{
	return q->head == q->tail && q->queued_vint_count == VINT_QUEUE_MAX;
}

/**
 * Queue the pending virtual interrupt for target vCPU.
 *
 * Returns true if successful in pushing a new entry to the queue, or false
 * otherwise.
 */
static bool vcpu_interrupt_queue_push(struct vcpu_locked vcpu_locked,
				      uint32_t vint_id)
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

	if (is_queue_full(q)) {
		return false;
	}

	/* Add the virtual interrupt to the queue. */
	q->vint_buffer[q->tail] = vint_id;
	q->tail = new_tail;

	assert(q->queued_vint_count < VINT_QUEUE_MAX);
	q->queued_vint_count++;

	return true;
}

/**
 * Remove an entry from the specified vCPU's queue at the head.
 * Returns true if successful in removing the entry, or false otherwise.
 */
static uint32_t vcpu_interrupt_queue_pop(struct vcpu_locked vcpu_locked)
{
	struct interrupt_queue *q;
	uint16_t new_head;
	uint32_t vint_id;

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	/* Check if queue is empty. */
	if (is_queue_empty(q)) {
		return HF_INVALID_INTID;
	}

	/*
	 * An entry is removed from the head of the queue. Once successful, the
	 * head is incremented or wrapped around if needed.
	 */
	new_head = queue_increment_index(q->head);
	vint_id = q->vint_buffer[q->head];
	q->head = new_head;

	assert(q->queued_vint_count > 0);
	q->queued_vint_count--;

	return vint_id;
}

/**
 * Look for the first pending virtual interrupt from the vcpu's queue. Note
 * that the entry is not removed from the queue.
 *
 * Returns true if a valid entry exists in the queue, or false otherwise.
 */
static uint32_t vcpu_interrupt_queue_peek(struct vcpu_locked vcpu_locked)
{
	struct interrupt_queue *q;
	uint32_t queued_vint;

	q = &vcpu_locked.vcpu->interrupts.vint_q;

	/* Check if queue is empty. */
	if (is_queue_empty(q)) {
		return HF_INVALID_INTID;
	}

	queued_vint = q->vint_buffer[q->head];
	assert(queued_vint != HF_INVALID_INTID);

	return queued_vint;
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
}

void vcpu_virt_interrupt_enable(struct vcpu_locked vcpu_locked,
				uint32_t vint_id, bool enable)
{
	struct interrupts *interrupts = &vcpu_locked.vcpu->interrupts;

	if (enable) {
		/*
		 * If it is pending and was not enabled before, increment the
		 * count.
		 */
		if (vcpu_is_virt_interrupt_pending(interrupts, vint_id) &&
		    !vcpu_is_virt_interrupt_enabled(interrupts, vint_id)) {
			vcpu_interrupt_count_increment(vcpu_locked, vint_id);
		}
		vcpu_virt_interrupt_set_enabled(interrupts, vint_id);
	} else {
		/*
		 * If it is pending and was enabled before, decrement the count.
		 */
		if (vcpu_is_virt_interrupt_pending(interrupts, vint_id) &&
		    vcpu_is_virt_interrupt_enabled(interrupts, vint_id)) {
			vcpu_interrupt_count_decrement(vcpu_locked, vint_id);
		}
		vcpu_virt_interrupt_clear_enabled(interrupts, vint_id);
	}
}

/*
 * Find and return the first intid that is pending and enabled, the interrupt
 * struct for this intid will be at the head of the list so can be popped later.
 */
uint32_t vcpu_virt_interrupt_peek_pending_and_enabled(
	struct vcpu_locked vcpu_locked)
{
	uint32_t vint_id;
	struct interrupts *interrupts = &vcpu_locked.vcpu->interrupts;
	uint32_t pending_and_enabled_count =
		vcpu_virt_interrupt_count_get(vcpu_locked);

	/* First check there is a pending and enabled interrupt to return. */
	if (pending_and_enabled_count == 0) {
		return HF_INVALID_INTID;
	}

	/*
	 * We know here there is a pending and enabled interrupt in
	 * the queue. So push any interrupts that are not enabled to
	 * the back of the queue until we reach the first enabled one.
	 */
	vint_id = vcpu_interrupt_queue_peek(vcpu_locked);
	while (!vcpu_is_virt_interrupt_enabled(interrupts, vint_id)) {
		vcpu_interrupt_queue_pop(vcpu_locked);
		vcpu_interrupt_queue_push(vcpu_locked, vint_id);
		vint_id = vcpu_interrupt_queue_peek(vcpu_locked);
	}

	assert(vint_id != HF_INVALID_INTID);

	return vint_id;
}

/*
 * Get the next pending and enabled virtual interrupt ID.
 * Pops from the queue and clears the bitmap.
 */
uint32_t vcpu_virt_interrupt_get_pending_and_enabled(
	struct vcpu_locked vcpu_locked)
{
	uint32_t vint_id =
		vcpu_virt_interrupt_peek_pending_and_enabled(vcpu_locked);

	if (vint_id != HF_INVALID_INTID) {
		vcpu_interrupt_queue_pop(vcpu_locked);
		vcpu_interrupt_clear_decrement(vcpu_locked, vint_id);
	}

	return vint_id;
}

/*
 * Set a virtual interrupt to pending. Add it to the queue and set the bitmap.
 */
void vcpu_virt_interrupt_inject(struct vcpu_locked vcpu_locked,
				uint32_t vint_id)
{
	struct interrupts *interrupts = &vcpu_locked.vcpu->interrupts;

	/*
	 * An interrupt can only be pending once so return if it is
	 * already pending.
	 */
	if (vcpu_is_virt_interrupt_pending(interrupts, vint_id)) {
		return;
	}

	/* Push to the queue and set the bitmap. */
	if (!vcpu_interrupt_queue_push(vcpu_locked, vint_id)) {
		dlog_verbose(
			"Exhausted interrupt queue for vCPU %u of SP %#x\n",
			vcpu_index(vcpu_locked.vcpu), vcpu_locked.vcpu->vm->id);
		assert(false);
		return;
	}
	vcpu_virt_interrupt_set_pending(interrupts, vint_id);

	if (vcpu_is_virt_interrupt_enabled(interrupts, vint_id)) {
		vcpu_interrupt_count_increment(vcpu_locked, vint_id);
	}
}

void vcpu_virt_interrupt_clear(struct vcpu_locked vcpu_locked, uint32_t vint_id)
{
	struct interrupts *interrupts = &vcpu_locked.vcpu->interrupts;
	uint32_t queued_vint_count = interrupts->vint_q.queued_vint_count;

	/* See if interrupt is pending and therefore needs to be cleared. */
	if (!vcpu_is_virt_interrupt_pending(interrupts, vint_id)) {
		return;
	}

	for (uint32_t i = 0; i < queued_vint_count; i++) {
		uint32_t intid = vcpu_interrupt_queue_pop(vcpu_locked);

		if (intid == vint_id) {
			vcpu_interrupt_clear_decrement(vcpu_locked, intid);
		} else {
			/*
			 * If the interrupt is not the one we wish to remove,
			 * inject it again. We must pop and push all interrupts
			 * to ensure the FIFO ordering is maintained.
			 */
			vcpu_interrupt_queue_push(vcpu_locked, intid);
		}
	}
}
