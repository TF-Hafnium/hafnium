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
#include "hf/arch/plat/psci.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/plat/interrupts.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "feature_id.h"
#include "msr.h"
#include "perfmon.h"
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

void arch_regs_reset(struct vcpu *vcpu)
{
	ffa_id_t vm_id = vcpu->vm->id;
	bool is_primary = vm_id == HF_PRIMARY_VM_ID;
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

	if (is_primary) {
		/*
		 * cnthctl_el2 is redefined when VHE is enabled.
		 * EL1PCTEN, don't trap phys cnt access.
		 * EL1PCEN, don't trap phys timer access.
		 */
		if (has_vhe_support()) {
			cnthctl |= (1U << 10) | (1U << 11);
		} else {
			cnthctl |= (1U << 0) | (1U << 1);
		}
	}

	r->hyp_state.hcr_el2 =
		get_hcr_el2_value(vm_id, vcpu->vm->el0_partition);
	r->hyp_state.sctlr_el2 = get_sctlr_el2_value(vcpu->vm->el0_partition);
	r->lazy.cnthctl_el2 = cnthctl;
	if (vcpu->vm->el0_partition) {
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

struct ffa_value arch_regs_get_args(struct arch_regs *regs)
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
		.extended_val.valid = false,
	};
}

/* Returns the SVE implemented VL in bytes (constrained by ZCR_EL3.LEN) */
static uint64_t arch_cpu_sve_len_get(void)
{
	uint64_t vl;

	__asm__ volatile(
		".arch_extension sve;"
		"rdvl %0, #1;"
		".arch_extension nosve;"
		: "=r"(vl));

	return vl;
}

static void arch_cpu_sve_configure_sve_vector_length(void)
{
	uint64_t vl_bits;
	uint32_t zcr_len;

	/*
	 * Set ZCR_EL2.LEN to the maximum vector length permitted by the
	 * architecture which applies to EL2 and lower ELs (limited by the
	 * HW implementation).
	 * This is done so that the VL read by arch_cpu_sve_len_get isn't
	 * constrained by EL2 and thus indirectly retrieves the value
	 * constrained by EL3 which applies to EL3 and lower ELs (limited by
	 * the HW implementation).
	 */
	write_msr(MSR_ZCR_EL2, ZCR_LEN_MAX);
	isb();

	vl_bits = arch_cpu_sve_len_get() << 3;
	zcr_len = (vl_bits >> 7) - 1;

	/*
	 * Set ZCR_EL2.LEN to the discovered value which contrains the VL at
	 * EL2 and lower ELs to the value set by EL3.
	 */
	write_msr(MSR_ZCR_EL2, zcr_len & ZCR_LEN_MASK);
	isb();
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

	if (is_arch_feat_sve_supported()) {
		arch_cpu_sve_configure_sve_vector_length();
	}

	plat_interrupts_controller_hw_init(c);
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
