/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

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
