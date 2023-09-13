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
 * Branch Target Identification mechanism support in AArch64 state.
 */
bool is_arch_feat_bti_supported(void);

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
 * Returns true if the SVE feature is implemented.
 */
bool is_arch_feat_sve_supported(void);
