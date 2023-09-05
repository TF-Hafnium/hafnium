/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "msr.h"
#include "sysregs.h"

void arch_sme_disable_traps(void)
{
	uint64_t cptr_el2_val;

	/* Disable SME traps at EL2/1/0. */
	cptr_el2_val = read_msr(CPTR_EL2);
	if (has_vhe_support()) {
		cptr_el2_val |= CPTR_EL2_SME_VHE_SMEN;
	} else {
		cptr_el2_val &= ~CPTR_EL2_TSM;
	}

	write_msr(CPTR_EL2, cptr_el2_val);
	isb();
}

void arch_sme_enable_traps(void)
{
	uint64_t cptr_el2_val;

	/* Enable SME traps at EL2/1/0. */
	cptr_el2_val = read_msr(CPTR_EL2);
	if (has_vhe_support()) {
		cptr_el2_val &= ~CPTR_EL2_SME_VHE_SMEN;
	} else {
		cptr_el2_val |= CPTR_EL2_TSM;
	}

	write_msr(CPTR_EL2, cptr_el2_val);
	isb();
}

void arch_sme_configure_svl(void)
{
	uint64_t smcr_el2_val;

	/*
	 * SMCR_EL2.FA64=1 treating A64 instructions as legal in Streaming SVE.
	 * EZT0 cleared traps accesses to SME2 ZT0 register at EL2 and lower.
	 * Set SVL to the maximum permitted value.
	 */
	smcr_el2_val = (SMCR_EL2_LEN_MAX << SMCR_EL2_LEN_SHIFT);
	if (is_arch_feat_sme_fa64_supported()) {
		smcr_el2_val |= SMCR_EL2_FA64_BIT;
	}

	write_msr(MSR_SMCR_EL2, smcr_el2_val);
	isb();
}
