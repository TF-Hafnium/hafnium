/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mm.h"
#include "hf/mpool.h"

/**
 * Performs arch specific boot time initialization.
 *
 * It must only be called once, on first boot and must be called as early as
 * possible.
 */
void arch_one_time_init(void);

/**
 * Updates the hypervisor page table such that the stack address range
 * is mapped into the address space at the corresponding address range in the
 * architecture-specific mode.
 */
bool arch_stack_mm_init(struct mm_stage1_locked stage1_locked,
			struct mpool *ppool);
