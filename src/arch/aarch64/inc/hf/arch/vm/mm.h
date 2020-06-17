/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mm.h"

bool arch_vm_mm_init(void);
void arch_vm_mm_enable(paddr_t table);

/**
 * Reset MMU-related system registers. Must be called after arch_vm_mm_init().
 */
void arch_vm_mm_reset(void);
