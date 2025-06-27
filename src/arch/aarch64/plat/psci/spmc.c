/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/psci.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/ffa/notifications.h"
#include "hf/vm.h"

#include "psci.h"

void cpu_entry(struct cpu *c);

/**
 * Returns zero in context of the SPMC as it does not rely
 * on the EL3 PSCI framework.
 */
uint32_t plat_psci_version_get(void)
{
	return 0;
}

/**
 * Initialize the platform power managment module in context of
 * running the SPMC.
 */
void plat_psci_init(void)
{
	struct ffa_value res;

	/*
	 * DEN0077A FF-A v1.1 Beta0 section 18.3.2.1.1
	 * Register the SPMC secondary cold boot entry point at the secure
	 * physical FF-A instance (to the SPMD).
	 */
	res = smc_ffa_call_ext(
		(struct ffa_value){.func = FFA_SECONDARY_EP_REGISTER_64,
				   .arg1 = (uintreg_t)&cpu_entry});

	if (res.func != FFA_SUCCESS_32 && res.func != FFA_SUCCESS_64) {
		panic("FFA_SECONDARY_EP_REGISTER_64 failed");
	}
}

void plat_psci_cpu_suspend(uint32_t power_state)
{
	(void)power_state;
}

/** Switch to the normal world vCPU pinned on this physical CPU now. */
static struct vcpu *plat_psci_switch_to_other_world(struct cpu *c)
{
	struct vcpu_locked other_world_vcpu_locked;
	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct vcpu *other_world_vcpu;

	CHECK(other_world_vm != NULL);

	other_world_vcpu = vm_get_vcpu(other_world_vm, cpu_index(c));

	CHECK(other_world_vcpu != NULL);

	other_world_vcpu_locked = vcpu_lock(other_world_vcpu);

	/*
	 * Return FFA_MSG_WAIT_32 to indicate to SPMD that SPMC
	 * has successfully finished initialization on this
	 * CPU.
	 */
	arch_regs_set_retval(&other_world_vcpu->regs,
			     (struct ffa_value){.func = FFA_MSG_WAIT_32});

	other_world_vcpu->state = VCPU_STATE_WAITING;
	vcpu_unlock(&other_world_vcpu_locked);

	return other_world_vcpu;
}

/**
 * Check if there is at least one SP whose execution context needs to be
 * bootstrapped on this physical CPU.
 */
static struct vm *plat_psci_get_boot_vm(struct cpu *c)
{
	struct vm *boot_vm;

	if (cpu_index(c) == PRIMARY_CPU_IDX) {
		boot_vm = vm_get_boot_vm();

		/*
		 * On the primary CPU, at least one SP will exist whose
		 * execution context shall be bootstrapped.
		 */
		CHECK(boot_vm != NULL);
	} else {
		boot_vm = vm_get_boot_vm_secondary_core();

		/*
		 * It is possible that no SP might exist that needs its
		 * execution context to be bootstrapped on secondary CPU. This
		 * can happen if all the SPs in the system are UP partitions and
		 * hence, have no vCPUs pinned to secondary CPUs.
		 */
		if (boot_vm != NULL) {
			assert(boot_vm->vcpu_count > 1);
		}
	}

	return boot_vm;
}

struct vcpu *plat_psci_cpu_resume(struct cpu *c)
{
	struct vcpu_locked vcpu_locked;
	struct vm *boot_vm;
	struct vcpu *boot_vcpu;

	cpu_on(c);

	arch_cpu_init(c);

	/* Initialize SRI for running core. */
	ffa_notifications_sri_init(c);

	boot_vm = plat_psci_get_boot_vm(c);

	if (boot_vm == NULL) {
		return plat_psci_switch_to_other_world(c);
	}

	/* Obtain the vCPU for the boot SP on this CPU. */
	boot_vcpu = vm_get_vcpu(boot_vm, cpu_index(c));

	/* Lock the vCPU to update its fields. */
	vcpu_locked = vcpu_lock(boot_vcpu);

	/* Pin the vCPU to this CPU. */
	boot_vcpu->cpu = c;

	vcpu_secondary_reset_and_start(vcpu_locked, boot_vcpu->vm->secondary_ep,
				       0ULL);

	/* Set the vCPU's state to STARTING. */
	CHECK(vcpu_state_set(vcpu_locked, VCPU_STATE_STARTING));
	boot_vcpu->regs_available = false;

	/* vCPU restarts in runtime model for SP initialization. */
	boot_vcpu->rt_model = RTM_SP_INIT;

	/* Set the designated GP register with the core linear id. */
	vcpu_set_phys_core_idx(boot_vcpu);

	if (cpu_index(c) == PRIMARY_CPU_IDX) {
		struct vm_locked vm_locked;

		vcpu_unlock(&vcpu_locked);
		vm_locked = vm_lock(boot_vm);
		vcpu_locked = vcpu_lock(boot_vcpu);
		vm_set_state(vm_locked, VM_STATE_RUNNING);
		vm_unlock(&vm_locked);

		/*
		 * Boot information is passed by the SPMC to the SP's execution
		 * context only on the primary CPU.
		 */
		vcpu_set_boot_info_gp_reg(boot_vcpu);
	}

	vcpu_unlock(&vcpu_locked);

	return boot_vcpu;
}
