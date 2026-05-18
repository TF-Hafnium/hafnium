/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"
extern "C" {
}

/* Define stacks for the CPUs in unit tests */
char callstacks[MAX_CPUS][STACK_SIZE];

namespace
{
} /* namespace */
