/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/barriers.h"
#include "hf/arch/types.h"

#include "msr.h"
#include "sysregs_defs.h"

/** HCR_EL2 */
uintreg_t get_hcr_el2_value(ffa_id_t vm_id, bool is_el0_partition);

/** MDCR_EL2 */
uintreg_t get_mdcr_el2_value(void);

/** CPTR_EL2 */
uintreg_t get_cptr_el2_value(void);

/** SCTLR_EL2 */
uintreg_t get_sctlr_el2_value(bool is_el0_partition);

/**
 * Returns true if the processor supports ARMv8.1 VHE.
 */
static inline bool has_vhe_support(void)
{
	return (((read_msr(ID_AA64MMFR1_EL1) >> ID_AA64MMFR1_EL1_VH_SHIFT) &
		 ID_AA64MMFR1_EL1_VH_MASK) == ID_AA64MMFR1_EL1_VH_SUPPORTED);
}

static inline void vhe_switch_to_host_or_guest(bool guest)
{
	if (has_vhe_support()) {
		uint64_t hcr_el2 = read_msr(hcr_el2);

		if (guest) {
			hcr_el2 &= ~HCR_EL2_TGE;
		} else {
			hcr_el2 |= HCR_EL2_TGE;
		}
		write_msr(hcr_el2, hcr_el2);
		isb();
	}
}

/**
 * Branch Target Identification mechanism support in AArch64 state.
 */
static inline bool is_arch_feat_bti_supported(void)
{
	uint64_t id_aa64pfr1_el1 = read_msr(ID_AA64PFR1_EL1);

	return (id_aa64pfr1_el1 & ID_AA64PFR1_EL1_BT) == 1ULL;
}

/**
 * Returns true if the RME feature is implemented.
 */
static inline bool is_arch_feat_rme_supported(void)
{
	return ((read_msr(ID_AA64PFR0_EL1) >> ID_AA64PFR0_EL1_RME_SHIFT) &
		ID_AA64PFR0_EL1_RME_MASK) != 0;
}

/**
 * Returns true if the SVE feature is implemented.
 */
static inline bool is_arch_feat_sve_supported(void)
{
	uint64_t id_aa64pfr0_el1 = read_msr(ID_AA64PFR0_EL1);

	return ((id_aa64pfr0_el1 >> ID_AA64PFR0_EL1_SVE_SHIFT) &
		ID_AA64PFR0_EL1_SVE_MASK) == ID_AA64PFR0_EL1_SVE_SUPPORTED;
}

/**
 * FEAT_SME/FEAT_SME2.
 */

/**
 * Returns true if FEAT_SME/FEAT_SME2 is implemented.
 */
static inline bool is_arch_feat_sme_supported(void)
{
	uint64_t id_aa64pfr1_el1 = read_msr(ID_AA64PFR1_EL1);

	return ((id_aa64pfr1_el1 >> ID_AA64PFR1_EL1_SME_SHIFT) &
		ID_AA64PFR1_EL1_SME_MASK) >= ID_AA64PFR1_EL1_SME_SUPPORTED;
}

/**
 * Returns true if FEAT_SME_FA64 is implemented.
 */
static inline bool is_arch_feat_sme_fa64_supported(void)
{
	uint64_t id_aa64smfr0_el1 = read_msr(MSR_ID_AA64SMFR0_EL1);

	return ((id_aa64smfr0_el1 >> ID_AA64SMFR0_EL1_FA64_SHIFT) &
		ID_AA64SMFR0_EL1_FA64_MASK) == ID_AA64SMFR0_EL1_FA64_SUPPORTED;
}

/**
 * Returns true if Pointer Authentication is implemented.
 */
static inline bool is_arch_feat_pauth_supported(void)
{
	uint64_t id_aa64isar1_el1 = read_msr(ID_AA64ISAR1_EL1);
	uint64_t id_aa64isar2_el1 = read_msr(ID_AA64ISAR2_EL1);

	return (((id_aa64isar1_el1 >> ID_AA64ISAR1_EL1_PAUTH_SHIFT) &
		 ID_AA64ISAR1_EL1_PAUTH_MASK) |
		((id_aa64isar2_el1 >> ID_AA64ISAR2_EL1_PAUTH_SHIFT) &
		 ID_AA64ISAR2_EL1_PAUTH_MASK)) != 0U;
}
