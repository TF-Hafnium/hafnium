/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"

/**
 * The stacks to be used by the CPUs.
 *
 * Align to page boundaries to ensure that cache lines are not shared between a
 * CPU's stack and data that can be accessed from other CPUs. If this did
 * happen, there may be coherency problems when the stack is being used before
 * caching is enabled.
 *
 * Define in assembly to enforce NOBITS attribute (allocated and initialized at load).
 */
	.section .stacks, "aw", %nobits
	.align 16
	.global callstacks

callstacks:
	.space (MAX_CPUS * STACK_SIZE)
