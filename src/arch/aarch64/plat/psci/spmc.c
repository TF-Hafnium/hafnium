/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/ffa.h"
#include "hf/arch/plat/psci.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/vm.h"

#include "vmapi/hf/types.h"

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
	res = smc_ffa_call(
		(struct ffa_value){.func = FFA_SECONDARY_EP_REGISTER_64,
				   .arg1 = (uintreg_t)&cpu_entry});

	if (res.func != FFA_SUCCESS_64) {
		panic("FFA_SECONDARY_EP_REGISTER_64 failed");
	}
}

void plat_psci_cpu_suspend(uint32_t power_state)
{
	(void)power_state;
}

struct vcpu *plat_psci_cpu_resume(struct cpu *c)
{
	struct vcpu_locked vcpu_locked;
	struct vcpu_locked other_world_vcpu_locked;
	struct vcpu *vcpu = vcpu_get_boot_vcpu();
	struct vm *vm;
	struct vm *other_world_vm;
	struct vcpu *other_world_vcpu;
	struct two_vcpu_locked vcpus_locked;

	assert(vcpu != NULL);

	vm = vcpu->vm;
	cpu_on(c);

	arch_cpu_init(c);

	/* Initialize SRI for running core. */
	plat_ffa_sri_init(c);

	vcpu = vm_get_vcpu(vm, vm_is_up(vm) ? 0 : cpu_index(c));
	vcpu_locked = vcpu_lock(vcpu);

	if (vcpu->rt_model != RTM_SP_INIT &&
	    vm_power_management_cpu_on_requested(vm) == false) {
		other_world_vm = vm_find(HF_OTHER_WORLD_ID);
		CHECK(other_world_vm != NULL);
		other_world_vcpu = vm_get_vcpu(other_world_vm, cpu_index(c));
		vcpu_unlock(&vcpu_locked);

		/* Lock both vCPUs at once to avoid deadlock. */
		vcpus_locked = vcpu_lock_both(vcpu, other_world_vcpu);
		vcpu_locked = vcpus_locked.vcpu1;
		other_world_vcpu_locked = vcpus_locked.vcpu2;

		vcpu = api_switch_to_other_world(
			other_world_vcpu_locked,
			(struct ffa_value){.func = FFA_MSG_WAIT_32},
			VCPU_STATE_WAITING);
		vcpu_unlock(&other_world_vcpu_locked);
		goto exit;
	}

	vcpu->cpu = c;

	vcpu_secondary_reset_and_start(vcpu_locked, vcpu->vm->secondary_ep,
				       0ULL);
	vcpu_set_running(vcpu_locked, NULL);

	/* vCPU restarts in runtime model for SP initialization. */
	vcpu->rt_model = RTM_SP_INIT;

	/* Set the designated GP register with the core linear id. */
	vcpu_set_phys_core_idx(vcpu);

	vcpu_set_boot_info_gp_reg(vcpu);

exit:
	vcpu_unlock(&vcpu_locked);

	return vcpu;
}
