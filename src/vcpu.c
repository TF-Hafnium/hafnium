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

static struct vcpu *boot_vcpu;

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
	vcpu->direct_request_origin_vm_id = HF_INVALID_VM_ID;
	vcpu->rt_model = RTM_SP_INIT;
	vcpu->next_boot = NULL;
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
			"Stage-%d page fault: pc=%#x, vmid=%#x, vcpu=%u, "
			"vaddr=%#x, ipaddr=%#x, mode=%#x %#x\n",
			current->vm->el0_partition ? 1 : 2, f->pc, vm->id,
			vcpu_index(current), f->vaddr, f->ipaddr, f->mode,
			mode);
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
 * Gets the first partition to boot, according to Boot Protocol from FFA spec.
 */
struct vcpu *vcpu_get_boot_vcpu(void)
{
	return boot_vcpu;
}

/**
 * Insert in boot list, sorted by `boot_order` parameter in the vm structure
 * and rooted in `first_boot_vm`.
 */
void vcpu_update_boot(struct vcpu *vcpu)
{
	struct vcpu *current = NULL;
	struct vcpu *previous = NULL;

	if (boot_vcpu == NULL) {
		boot_vcpu = vcpu;
		return;
	}

	current = boot_vcpu;

	while (current != NULL &&
	       current->vm->boot_order <= vcpu->vm->boot_order) {
		previous = current;
		current = current->next_boot;
	}

	if (previous != NULL) {
		previous->next_boot = vcpu;
	} else {
		boot_vcpu = vcpu;
	}

	vcpu->next_boot = current;
}
