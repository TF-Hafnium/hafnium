/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#ifndef __ASSEMBLER__

#pragma once

#include <stddef.h>

#include "hf/arch/cpu.h"

/**
 * Macros to stringify a parameter, and to allow the results of a macro to be
 * stringified in turn.
 */
#define str_(s) #s
#define str(s) str_(s)

/**
 * Reads a system register, supported by the current assembler, and returns the
 * result.
 */
#define read_msr(name)                                              \
	__extension__({                                             \
		uintreg_t __v;                                      \
		__asm__ volatile("mrs %0, " str(name) : "=r"(__v)); \
		__v;                                                \
	})

/**
 * Writes the value to the system register, supported by the current assembler.
 */
#define write_msr(name, value)                                \
	__extension__({                                       \
		__asm__ volatile("msr " str(name) ", %x0"     \
				 :                            \
				 : "rZ"((uintreg_t)(value))); \
	})

#endif /* __ASSEMBLER__ */

/*
 * Encodings for registers supported after Armv8.0.
 * We aim to build one binary that supports a variety of platforms, therefore,
 * use encodings in Arm Architecture Reference Manual Armv8-a, D13.2 for
 * registers supported after Armv8.0.
 */

/*
 * Registers supported from Armv8.1 onwards.
 */

/*
 * Registers for feature Armv8.1-LOR (Limited Ordering Regions).
 */

/**
 * Encoding for the LORegion Control register (LORC_EL1).
 * This register enables and disables LORegions (Armv8.1).
 */
#define MSR_LORC_EL1 S3_0_C10_C4_3

/*
 * Registers supported from Armv8.4 onwards.
 */

/*
 * VSTTBR_EL2, Virtualization Secure Translation Table Base Register
 */
#define MSR_VSTTBR_EL2 S3_4_C2_C6_0

/*
 * VSTCR_EL2, Virtualization Secure Translation Control Register
 */
#define MSR_VSTCR_EL2 S3_4_C2_C6_2

/*
 * SVE Control Register for EL2.
 */
#define MSR_ZCR_EL2 S3_4_C1_C2_0

#if BRANCH_PROTECTION

#define APIAKEYLO_EL1 S3_0_C2_C1_0
#define APIAKEYHI_EL1 S3_0_C2_C1_1
#define APIBKEYLO_EL1 S3_0_C2_C1_2
#define APIBKEYHI_EL1 S3_0_C2_C1_3
#define APDAKEYLO_EL1 S3_0_C2_C2_0
#define APDAKEYHI_EL1 S3_0_C2_C2_1
#define APDBKEYLO_EL1 S3_0_C2_C2_2
#define APDBKEYHI_EL1 S3_0_C2_C2_3
#define APGAKEYLO_EL1 S3_0_C2_C3_0
#define APGAKEYHI_EL1 S3_0_C2_C3_1

#endif

/*
 * EL1 register encodings when ARMv8.1 VHE is enabled, as defined in table
 * D5-47 of the ARMv8 ARM (DDI0487F).
 */
#define MSR_SCTLR_EL12 S3_5_C1_C0_0
#define MSR_CPACR_EL12 S3_5_C1_C0_2
#define MSR_ZCR_EL12 S3_5_C1_C2_0
#define MSR_TRFCR_EL12 S3_5_C1_C2_1
#define MSR_TTBR0_EL12 S3_5_C2_C0_0
#define MSR_TTBR1_EL12 S3_5_C2_C0_1
#define MSR_TCR_EL12 S3_5_C2_C0_2
#define MSR_AFSR0_EL12 S3_5_C5_C1_0
#define MSR_AFSR1_EL12 S3_5_C5_C1_1
#define MSR_ESR_EL12 S3_5_C5_C2_0
#define MSR_FAR_EL12 S3_5_C6_C0_0
#define MSR_PMSCR_EL12 S3_5_C9_C9_0
#define MSR_MAIR_EL12 S3_5_C10_C2_0
#define MSR_AMAIR_EL12 S3_5_C10_C3_0
#define MSR_VBAR_EL12 S3_5_C12_C0_0
#define MSR_CONTEXTIDR_EL12 S3_5_C13_C0_1
#define MSR_CNTKCTL_EL12 S3_5_C14_C1_0
#define MSR_CNTP_TVAL_EL02 S3_5_C14_C2_0
#define MSR_CNTP_CTL_EL02 S3_5_C14_C2_1
#define MSR_CNTP_CVAL_EL02 S3_5_C14_C2_2
#define MSR_CNTV_TVAL_EL02 S3_5_C14_C3_0
#define MSR_CNTV_CTL_EL02 S3_5_C14_C3_1
#define MSR_CNTV_CVAL_EL02 S3_5_C14_C3_2
#define MSR_SPSR_EL12 S3_5_C4_C0_0
#define MSR_ELR_EL12 S3_5_C4_C0_1

/**
 * Host(EL2/S-EL2) physical timer register encodings.
 */
#define MSR_CNTHP_CTL_EL2 S3_4_C14_C2_1
#define MSR_CNTHP_CVAL_EL2 S3_4_C14_C2_2
#define MSR_CNTHP_TVAL_EL2 S3_4_C14_C2_0
#define MSR_CNTHPS_CTL_EL2 S3_4_C14_C5_1
#define MSR_CNTHPS_CVAL_EL2 S3_4_C14_C5_2
#define MSR_CNTHPS_TVAL_EL2 S3_4_C14_C5_0

/**
 * FEAT_SME
 */

/* SME Feature ID register 0. */
#define MSR_ID_AA64SMFR0_EL1 S3_0_C0_C4_5

#define MSR_SMCR_EL2 S3_4_C1_C2_6

#define SMCR_EL2_LEN_SHIFT UINT64_C(0)
#define SMCR_EL2_LEN_MAX UINT64_C(0xf)
#define SMCR_EL2_FA64_BIT (UINT64_C(1) << 31)

#define MSR_SVCR S3_3_C4_C2_2
#define MSR_SVCR_ZA (UINT64_C(1) << 1)
#define MSR_SVCR_SM (UINT64_C(1) << 0)
