/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sysregs.h"

#include "msr.h"

/**
 * RAS Extension version.
 */
#define ID_AA64PFR0_EL1_RAS (UINT64_C(0xf) << 28)

/**
 * Returns true if the current processor supports the RAS extension.
 */
static bool has_ras_support(void)
{
	return read_msr(ID_AA64PFR0_EL1) & ID_AA64PFR0_EL1_RAS;
}

/**
 * Returns the value for HCR_EL2 for the particular VM.
 * For now, the primary VM has one value and all secondary VMs share a value.
 */
uintreg_t get_hcr_el2_value(ffa_id_t vm_id, bool is_el0_partition)
{
	uintreg_t hcr_el2_value = 0;

	/* Baseline values for all VMs. */

	/*
	 * Trap access to registers in ID group 3. These registers report on
	 * the underlying support for CPU features. Because Hafnium restricts
	 * certain features, e.g., RAS, it should emulate access to these
	 * registers to report the correct set of features supported.
	 */
	hcr_el2_value |= HCR_EL2_TID3;

	/* Execution state for EL1 is AArch64. */
	hcr_el2_value |= HCR_EL2_RW;

	/* Trap implementation registers and functionality. */
	hcr_el2_value |= HCR_EL2_TACR | HCR_EL2_TIDCP;

	/* Trap SMC instructions. */
	hcr_el2_value |= HCR_EL2_TSC;

	/*
	 * Translation table access made as part of a stage 1 translation
	 * table walk is subject to a stage 2 translation;
	 */
	hcr_el2_value |= HCR_EL2_PTW;

#if ENABLE_MTE
	/* Allow access to MTE allocation tags. */
	hcr_el2_value |= HCR_EL2_ATA;

	/* Do not trap access to group 5 for MTE. */
	hcr_el2_value &= ~HCR_EL2_TID5;
#endif

	/* Enable stage 2 address translation;*/
	hcr_el2_value |= HCR_EL2_VM;

	/* Trap cache maintenance instructions that operate by Set/Way. */
	hcr_el2_value |= HCR_EL2_TSW;

	/* Do *not* trap PAuth. APK and API bits *disable* trapping when set. */
	hcr_el2_value |= HCR_EL2_APK | HCR_EL2_API;

	/* Baseline values for all secondary VMs. */
	if (vm_id != HF_PRIMARY_VM_ID) {
		/*
		 * Set the minimum shareability domain to barrier instructions
		 * as inner shareable.
		 */
		hcr_el2_value |= HCR_EL2_BSU_INNER_SHAREABLE;

		/*
		 * Broadcast instructions related to invalidating the TLB within
		 * the Inner Shareable domain.
		 */
		hcr_el2_value |= HCR_EL2_FB;

		if (!has_ras_support()) {
			/*
			 * Trap SErrors into EL2 if the processor does not
			 * support RAS, because without error synchronization
			 * barriers, isolating SErrors could impose a high
			 * overhead. RAS is mandatory from Armv8.2, so this
			 * should not be common.
			 */
			hcr_el2_value |= HCR_EL2_AMO;
		}

		/*
		 * Route physical IRQ/FIQ interrupts to EL2. Do not route
		 * SError exceptions to EL2 (AMO). Instead let each VM handle
		 * it. Not setting AMO requires explicit Error Synchronisation
		 * Barrier instructions (esb) on hypervisor entry/exit, or
		 * implicit barriers (SCTLR_EL2_IESB is set).
		 */
		hcr_el2_value |= HCR_EL2_IMO | HCR_EL2_FMO;

#if SECURE_WORLD == 0
		/* Trap wait for event/interrupt instructions. */
		hcr_el2_value |= HCR_EL2_TWE | HCR_EL2_TWI;

#endif
	}

	/* Enable VHE, if enabled by build and if HW supports it. */
	if (has_vhe_support()) {
		hcr_el2_value |= HCR_EL2_E2H;
		if (is_el0_partition) {
			hcr_el2_value |= HCR_EL2_TGE;
		}
	}

	return hcr_el2_value;
}

/**
 * Returns the default value for MDCR_EL2.
 */
uintreg_t get_mdcr_el2_value(void)
{
	uintreg_t mdcr_el2_value = read_msr(MDCR_EL2);
	uintreg_t pmcr_el0 = read_msr(PMCR_EL0);

	/* Baseline values for all VMs. */

	/* Disable cycle and event counting at EL2. */
	mdcr_el2_value |= MDCR_EL2_HCCD | MDCR_EL2_HPMD;

	/* All available event counters accessible from all exception levels. */
	mdcr_el2_value |= GET_PMCR_EL0_N(pmcr_el0) & MDCR_EL2_HPMN;

	return mdcr_el2_value;
}

/**
 * Returns the value for CPTR_EL2 for the CPU.
 */
uintreg_t get_cptr_el2_value(void)
{
	uintreg_t ret;

	/*
	 * Do not trap Advanced SIMD access.
	 * Trap SVE, SME, trace and AMU system register accesses.
	 */
	if (has_vhe_support()) {
		ret = CPTR_EL2_VHE_FPEN | CPTR_EL2_VHE_TTA | CPTR_EL2_TAM;
	} else {
		ret = CPTR_EL2_TTA | CPTR_EL2_TAM;

		if (is_arch_feat_sve_supported()) {
			ret |= CPTR_EL2_TZ;
		}

		if (is_arch_feat_sme_supported()) {
			ret |= CPTR_EL2_TSM;
		}
	}

	return ret;
}

/**
 * Returns the value for SCTLR_EL2 for the CPU.
 */
uintreg_t get_sctlr_el2_value(bool is_el0_partition)
{
	uintreg_t sctlr_el2_value = 0;

	/*
	 * Implicit Error Synchronization Barrier (Armv8.2-IESB). This feature
	 * is mandatory from Armv8.2 onwards.
	 * Hafnium uses it to ensure that all SError exceptions are caught by
	 * the VM responsible for it.
	 */
	sctlr_el2_value |= SCTLR_EL2_IESB;

	/* MMU-related bits. */
	sctlr_el2_value |= SCTLR_EL2_M;

	/*
	 * Alignment check enabled, but in the case of an EL0 partition
	 * with VHE enabled.
	 */
	if (!(has_vhe_support() && is_el0_partition)) {
		sctlr_el2_value |= SCTLR_EL2_A;
	}
	sctlr_el2_value |= SCTLR_EL2_C;
	sctlr_el2_value |= SCTLR_EL2_SA;
	sctlr_el2_value |= SCTLR_EL2_I;
	sctlr_el2_value |= SCTLR_EL2_WXN;

#if ENABLE_MTE
	/* Allow access to Allocations tags at EL2 */
	sctlr_el2_value |= SCTLR_EL2_ATA;

	/* Tag Check Faults in EL2 cause precise synchronous exceptions. */
	sctlr_el2_value |= ((SCTLR_EL2_TCF_MASK & 1) << SCTLR_EL2_TCF_SHIFT);
#endif

#if BRANCH_PROTECTION
	/* Enable pointer authentication for instructions. */
	sctlr_el2_value |= SCTLR_EL2_ENIA;

	/* PACIASP/PACIBSP are compatible with PSTATE.BTYPE==11b. */
	sctlr_el2_value &= ~SCTLR_EL2_BT;
#endif

	/* RES1 Bits. */
	sctlr_el2_value |= SCTLR_EL2_B4;
	sctlr_el2_value |= SCTLR_EL2_B16;
	sctlr_el2_value |= SCTLR_EL2_B18;
	sctlr_el2_value |= SCTLR_EL2_B28;

	/* Unsupported features that otherwise are RES1. */
	sctlr_el2_value |= SCTLR_EL2_EOS;
	sctlr_el2_value |= SCTLR_EL2_EIS;

	return sctlr_el2_value;
}
