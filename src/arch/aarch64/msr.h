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
