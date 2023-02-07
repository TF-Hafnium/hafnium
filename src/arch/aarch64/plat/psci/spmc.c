/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"
#include "hf/dlog.h"
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

void plat_psci_cpu_resume(struct cpu *c, ipaddr_t entry_point)
{
	struct vcpu *vcpu = vcpu_get_boot_vcpu();
	struct vm *vm = vcpu->vm;
	struct vcpu_locked vcpu_locked;

	if (!cpu_on(c)) {
		vcpu = vm_get_vcpu(vm, cpu_index(c));
		vcpu_locked = vcpu_lock(vcpu);
		vcpu_on(vcpu_locked, entry_point, 0LL);
		vcpu_unlock(&vcpu_locked);
	}
}
