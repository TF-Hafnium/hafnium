/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/ffa.h"

#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

/**
 * The entry point of CPUs when they are turned on. It is supposed to initialise
 * all state and return the first vCPU to run.
 */
struct vcpu *cpu_main(struct cpu *c)
{
	struct vcpu *boot_vcpu = vcpu_get_boot_vcpu();
	struct vcpu *vcpu;

	/*
	 * Get the pinned vCPU from which Hafnium booted.
	 * This is the boot vCPU from PVM in the normal world and
	 * the first booted Secure Partition in the secure world.
	 */
	vcpu = vm_get_vcpu(boot_vcpu->vm, cpu_index(c));

	vcpu->cpu = c;

	/* Reset the registers to give a clean start for vCPU. */
	vcpu_reset(vcpu);

	/* Set the designated GP with the physical core index. */
	vcpu_set_phys_core_idx(vcpu);

	/* Initialize SRI for running core. */
	plat_ffa_sri_init(c);

	vcpu_set_boot_info_gp_reg(vcpu);

	return vcpu;
}
