/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/cpu.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hf/arch/gicv3.h"
#include "hf/arch/host_timer.h"
#include "hf/arch/plat/psci.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/hf_ipi.h"
#include "hf/plat/interrupts.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "feature_id.h"
#include "msr.h"
#include "perfmon.h"
#include "plat/prng/prng.h"
#include "sysregs.h"

#if BRANCH_PROTECTION

__uint128_t pauth_apia_key;

#endif

#if ENABLE_MTE

/* MTE hypervisor seed. */
uintptr_t mte_seed;

#endif

/**
 * The LO field indicates whether LORegions are supported.
 */
#define ID_AA64MMFR1_EL1_LO (UINT64_C(1) << 16)

static void lor_disable(void)
{
#if SECURE_WORLD == 0
	/*
	 * Accesses to LORC_EL1 are undefined if LORegions are not supported.
	 */
	if (read_msr(ID_AA64MMFR1_EL1) & ID_AA64MMFR1_EL1_LO) {
		write_msr(MSR_LORC_EL1, 0);
	}
#endif
}

static void gic_regs_reset(struct arch_regs *r, bool is_primary)
{
	(void)r;
	(void)is_primary;

#if GIC_VERSION == 3 || GIC_VERSION == 4
	uint32_t ich_hcr = 0;
	uint32_t icc_sre_el2 =
		(1U << 0) | /* SRE, enable ICH_* and ICC_* at EL2. */
		(0x3 << 1); /* DIB and DFB, disable IRQ/FIQ bypass. */

	if (is_primary) {
		icc_sre_el2 |= 1U << 3; /* Enable EL1 access to ICC_SRE_EL1. */
	} else {
		/* Trap EL1 access to GICv3 system registers. */
		ich_hcr =
			(0x1fU << 10); /* TDIR, TSEI, TALL1, TALL0, TC bits. */
	}
	r->gic.ich_hcr_el2 = ich_hcr;
	r->gic.icc_sre_el2 = icc_sre_el2;
#endif
}

static void pauth_el0_keys_reset(struct arch_regs *r)
{
	(void)r;

#if BRANCH_PROTECTION
	if (is_arch_feat_pauth_supported()) {
		__uint128_t apia_key_for_el0 = plat_prng_get_number();

		r->pac.apiakeylo_el1 =
			(uint64_t)(apia_key_for_el0 & UINT64_MAX);
		r->pac.apiakeyhi_el1 = (uint64_t)(apia_key_for_el0 >> 64);
	}
#endif
}

void arch_regs_reset(struct vcpu *vcpu)
{
	ffa_id_t vm_id = vcpu->vm->id;
	bool is_primary = vm_is_primary(vcpu->vm);
	cpu_id_t vcpu_id = is_primary ? vcpu->cpu->id : vcpu_index(vcpu);

	paddr_t table = vcpu->vm->ptable.root;
	struct arch_regs *r = &vcpu->regs;
	uintreg_t pc = r->pc;
	uintreg_t arg = r->r[0];
	uintreg_t cnthctl;

	memset_s(r, sizeof(*r), 0, sizeof(*r));

	r->pc = pc;
	r->r[0] = arg;

	cnthctl = 0;

	/*
	 * EL0PTEN  = 0: Trap EL0 access to physical timer registers.
	 * EL0PCTEN = 1: Don't trap EL0 access to physical counter and
	 *               frequency register.
	 * EL1PCEN  = 0: Trap EL1 access to physical timer registers.
	 * EL1PCTEN = 1: Don't trap EL1 access to physical counter.
	 */
	if (vcpu->vm->el0_partition) {
		cnthctl |= CNTHCTL_EL2_VHE_EL0PCTEN;
	} else {
		cnthctl |= CNTHCTL_EL2_VHE_EL1PCTEN;
	}

	r->hyp_state.cptr_el2 = get_cptr_el2_value();
	if (is_primary) {
		/* Do not trap FPU/Adv. SIMD/SVE/SME in the primary VM. */
		if (has_vhe_support()) {
			r->hyp_state.cptr_el2 |=
				(CPTR_EL2_VHE_ZEN | CPTR_EL2_VHE_FPEN |
				 CPTR_EL2_SME_VHE_SMEN);
		} else {
			r->hyp_state.cptr_el2 &=
				~(CPTR_EL2_TFP | CPTR_EL2_TZ | CPTR_EL2_TSM);
		}
	}

	r->hyp_state.hcr_el2 =
		get_hcr_el2_value(vm_id, vcpu->vm->el0_partition);
	r->hyp_state.sctlr_el2 = get_sctlr_el2_value(vcpu->vm->el0_partition);
	r->lazy.cnthctl_el2 = cnthctl;
	if (vcpu->vm->el0_partition) {
		pauth_el0_keys_reset(r);

		CHECK(has_vhe_support());
		/*
		 * AArch64 hafnium only uses 8 bit ASIDs at the moment.
		 * TCR_EL2.AS is set to 0, and per the Arm ARM, the upper 8 bits
		 * are ignored and treated as 0. There is no need to mask the
		 * VMID (used as asid) to only 8 bits.
		 */
		r->hyp_state.ttbr0_el2 =
			pa_addr(table) | ((uint64_t)vm_id << 48);
		r->spsr = PSR_PE_MODE_EL0T;
	} else {
		r->hyp_state.ttbr0_el2 = read_msr(ttbr0_el2);
		r->lazy.vtcr_el2 = arch_mm_get_vtcr_el2();
#if SECURE_WORLD == 0
		/*
		 * For a VM managed by the Hypervisor a single set
		 * of NS S2 PT exists.
		 * vttbr_el2 points to the single S2 root PT.
		 */
		r->lazy.vttbr_el2 = pa_addr(table) | ((uint64_t)vm_id << 48);
#else
		/*
		 * For a SP managed by the SPMC both sets of NS and secure
		 * S2 PTs exist.
		 * vttbr_el2 points to the NS S2 root PT.
		 * vsttbr_el2 points to secure S2 root PT.
		 */
		r->lazy.vttbr_el2 = pa_addr(vcpu->vm->arch.ptable_ns.root) |
				    ((uint64_t)vm_id << 48);
		r->lazy.vstcr_el2 = arch_mm_get_vstcr_el2();
		r->lazy.vsttbr_el2 = pa_addr(table);
#endif

		r->lazy.vmpidr_el2 = vcpu_id;
		/* Mask (disable) interrupts and run in EL1h mode. */
		r->spsr = PSR_D | PSR_A | PSR_I | PSR_F | PSR_PE_MODE_EL1H;

		r->lazy.mdcr_el2 = get_mdcr_el2_value();

		/*
		 * NOTE: It is important that MDSCR_EL1.MDE (bit 15) is set to 0
		 * for secondary VMs as long as Hafnium does not support debug
		 * register access for secondary VMs. If adding Hafnium support
		 * for secondary VM debug register accesses, then on context
		 * switches Hafnium needs to save/restore EL1 debug register
		 * state that either might change, or that needs to be
		 * protected.
		 */
		r->lazy.mdscr_el1 = 0x0U & ~(0x1U << 15);

		/* Disable cycle counting on initialization. */
		r->lazy.pmccfiltr_el0 =
			perfmon_get_pmccfiltr_el0_init_value(vm_id);

		/* Set feature-specific register values. */
		feature_set_traps(vcpu->vm, r);
	}

	gic_regs_reset(r, is_primary);
}

void arch_regs_set_pc_arg(struct arch_regs *r, ipaddr_t pc, uintreg_t arg)
{
	r->pc = ipa_addr(pc);
	r->r[0] = arg;
}

bool arch_regs_reg_num_valid(const unsigned int gp_reg_num)
{
	return gp_reg_num < NUM_GP_REGS;
}

void arch_regs_set_gp_reg(struct arch_regs *r, const uintreg_t value,
			  const unsigned int gp_reg_num)
{
	assert(arch_regs_reg_num_valid(gp_reg_num));
	r->r[gp_reg_num] = value;
}

void arch_regs_set_retval(struct arch_regs *r, struct ffa_value v)
{
	r->r[0] = v.func;
	r->r[1] = v.arg1;
	r->r[2] = v.arg2;
	r->r[3] = v.arg3;
	r->r[4] = v.arg4;
	r->r[5] = v.arg5;
	r->r[6] = v.arg6;
	r->r[7] = v.arg7;

	if (v.extended_val.valid) {
		r->r[8] = v.extended_val.arg8;
		r->r[9] = v.extended_val.arg9;
		r->r[10] = v.extended_val.arg10;
		r->r[11] = v.extended_val.arg11;
		r->r[12] = v.extended_val.arg12;
		r->r[13] = v.extended_val.arg13;
		r->r[14] = v.extended_val.arg14;
		r->r[15] = v.extended_val.arg15;
		r->r[16] = v.extended_val.arg16;
		r->r[17] = v.extended_val.arg17;
	}
}

static struct ffa_value arch_regs_get_args_ext(struct arch_regs *regs)
{
	return (struct ffa_value){
		.func = regs->r[0],
		.arg1 = regs->r[1],
		.arg2 = regs->r[2],
		.arg3 = regs->r[3],
		.arg4 = regs->r[4],
		.arg5 = regs->r[5],
		.arg6 = regs->r[6],
		.arg7 = regs->r[7],
		.extended_val.valid = true,
		.extended_val.arg8 = regs->r[8],
		.extended_val.arg9 = regs->r[9],
		.extended_val.arg10 = regs->r[10],
		.extended_val.arg11 = regs->r[11],
		.extended_val.arg12 = regs->r[12],
		.extended_val.arg13 = regs->r[13],
		.extended_val.arg14 = regs->r[14],
		.extended_val.arg15 = regs->r[15],
		.extended_val.arg16 = regs->r[16],
		.extended_val.arg17 = regs->r[17],
	};
}

struct ffa_value arch_regs_get_args(struct arch_regs *regs)
{
	uint32_t func_id = regs->r[0];

	if (func_id == FFA_MSG_SEND_DIRECT_REQ2_64 ||
	    func_id == FFA_MSG_SEND_DIRECT_RESP2_64 ||
	    (func_id == FFA_CONSOLE_LOG_64 &&
	     FFA_VERSION_1_2 <= FFA_VERSION_COMPILED)) {
		return arch_regs_get_args_ext(regs);
	}

	return (struct ffa_value){
		.func = func_id,
		.arg1 = regs->r[1],
		.arg2 = regs->r[2],
		.arg3 = regs->r[3],
		.arg4 = regs->r[4],
		.arg5 = regs->r[5],
		.arg6 = regs->r[6],
		.arg7 = regs->r[7],
		.extended_val.valid = false,
	};
}

void arch_cpu_init(struct cpu *c)
{
	/*
	 * Linux expects LORegions to be disabled, hence if the current system
	 * supports them, Hafnium ensures that they are disabled.
	 */
	lor_disable();

	write_msr(CPTR_EL2, get_cptr_el2_value());

	/* Initialize counter-timer virtual offset register to 0. */
	write_msr(CNTVOFF_EL2, 0);
	isb();

	plat_interrupts_controller_hw_init(c);

	/*
	 * Initialize the interrupt associated with S-EL2 physical timer for
	 * running core.
	 */
	host_timer_init();

	/* Initialise IPIs for the current cpu. */
	hf_ipi_init_interrupt();
}

struct vcpu *arch_vcpu_resume(struct cpu *c)
{
	return plat_psci_cpu_resume(c);
}

uint32_t arch_affinity_to_core_pos(uint64_t reg)
{
	struct cpu *this_cpu;
	uint32_t core_id;

	this_cpu = cpu_find(reg & MPIDR_AFFINITY_MASK);

	if (this_cpu == NULL) {
		/*
		 * There might be holes in all redistributor frames (some CPUs
		 * don't exist). For these CPUs, return MAX_CPUS, so that the
		 * caller has a chance to recover.
		 */
		core_id = MAX_CPUS;
	} else {
		core_id = cpu_index(this_cpu);
	}

	return core_id;
}

uint32_t arch_find_core_pos(void)
{
	uint32_t core_id;

	core_id = arch_affinity_to_core_pos(read_msr(MPIDR_EL1));
	CHECK(core_id < MAX_CPUS);

	return core_id;
}
