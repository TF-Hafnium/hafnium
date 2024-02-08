/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "msr.h"
#include "sysregs.h"

/** Disable FPU/Adv. SIMD/SVE traps. */
void arch_sve_disable_traps(void)
{
	uint64_t cptr_el2_val;

	cptr_el2_val = read_msr(CPTR_EL2);
	/* Disable Adv. SIMD/SVE traps at EL2/1/0. */
	if (has_vhe_support()) {
		cptr_el2_val |= (CPTR_EL2_VHE_ZEN | CPTR_EL2_VHE_FPEN);
	} else {
		cptr_el2_val &= ~(CPTR_EL2_TFP | CPTR_EL2_TZ);
	}

	write_msr(CPTR_EL2, cptr_el2_val);
	isb();
}

/** Enable SVE traps (but leave FPU/Adv. SIMD traps disabled). */
void arch_sve_enable_traps(void)
{
	uint64_t cptr_el2_val;

	cptr_el2_val = read_msr(CPTR_EL2);
	/* Enable SVE traps, disable Adv. SIMD traps at EL2/1/0. */
	if (has_vhe_support()) {
		cptr_el2_val &= ~CPTR_EL2_VHE_ZEN;
		cptr_el2_val |= CPTR_EL2_VHE_FPEN;
	} else {
		cptr_el2_val &= ~CPTR_EL2_TFP;
		cptr_el2_val |= CPTR_EL2_TZ;
	}

	write_msr(CPTR_EL2, cptr_el2_val);
	isb();
}

/** Returns the SVE implemented VL in bytes (constrained by ZCR_EL3.LEN) */
static uint64_t arch_sve_vector_length_get(void)
{
	uint64_t vl;

	__asm__ volatile(
		".arch_extension sve;"
		"rdvl %0, #1;"
		".arch_extension nosve;"
		: "=r"(vl));

	return vl;
}

void arch_sve_configure_vector_length(void)
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

	vl_bits = arch_sve_vector_length_get() << 3;
	zcr_len = (vl_bits >> 7) - 1;

	/*
	 * Set ZCR_EL2.LEN to the discovered value which contrains the VL at
	 * EL2 and lower ELs to the value set by EL3.
	 */
	write_msr(MSR_ZCR_EL2, zcr_len & ZCR_LEN_MASK);
	isb();
}
