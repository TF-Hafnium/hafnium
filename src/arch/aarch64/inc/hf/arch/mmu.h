/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/barriers.h"
/** AArch64-specific mapping modes */

/** Mapping mode defining MMU Stage-1 block/page non-secure bit */
#define MM_MODE_NS (1U << 7)

/** Page mapping mode for tagged normal memory. */
#define MM_MODE_T (1U << 10)

#define tlbi(op)                               \
	do {                                   \
		__asm__ volatile("tlbi " #op); \
	} while (0)
#define tlbi_reg(op, reg)                                              \
	do {                                                           \
		__asm__ __volatile__("tlbi " #op ", %0" : : "r"(reg)); \
	} while (0)

#if WORKAROUND_CVE_2025_10263

/*
 * Erratum CVE-2025-10263:
 *
 * The workaround is required after TLBI maintenance affecting
 * Stage-1 translation information (including combined Stage-1 +
 * Stage-2 invalidation), but is not required for invalidation
 * affecting only Stage-2 information.
 *
 * Complete the original TLBI maintenance sequence and issue the
 * additional TLBI+DSB required by the erratum.
 *
 * The additional TLBI does not need to target the same translation
 * regime as preceding TLBI operations. When executing at EL2, either
 * ( TLBI VALE1IS, XZR ) or ( TLBI VALE2IS, XZR ) is sufficient, provided
 * the operation is broadcast to the PEs affected by the erratum.
 *
 * VALE2IS is preferred at EL2 to minimize impact on the guest EL1&0
 * Stage-1 translation regime. For EL1 builds, use the corresponding
 * EL1 Stage-1 TLBI.
 */
static inline void arch_mm_tlbi_erratum_sync(void)
{
	dsb(ish);
	if (VM_TOOLCHAIN == 1) {
		/* EL1 Stage-1 translation regime. */
		__asm__ volatile("tlbi vale1is, xzr");
	} else {
		/* EL2 Stage-1 translation regime. */
		__asm__ volatile("tlbi vale2is, xzr");
	}
	dsb(ish);
}
#else
static inline void arch_mm_tlbi_erratum_sync(void)
{
	dsb(ish);
}
#endif /* WORKAROUND_CVE_2025_10263 */
