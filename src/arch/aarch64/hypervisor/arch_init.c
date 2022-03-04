/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/init.h"
#include "hf/arch/mmu.h"
#include "hf/arch/plat/psci.h"

#include "hf/layout.h"

/**
 * Performs arch specific boot time initialization.
 */
void arch_one_time_init(void)
{
	plat_psci_init();
}

/**
 * Updates the hypervisor page table such that the stack address range
 * is mapped into the address space at the corresponding address range in the
 * architecture-specific mode.
 */
bool arch_stack_mm_init(struct mm_stage1_locked stage1_locked,
			struct mpool *ppool)
{
#if ENABLE_MTE
	return mm_identity_map(stage1_locked, layout_stacks_begin(),
			       layout_stacks_end(),
			       MM_MODE_R | MM_MODE_W | MM_MODE_T, ppool);
#else
	return mm_identity_map(stage1_locked, layout_stacks_begin(),
			       layout_stacks_end(), MM_MODE_R | MM_MODE_W,
			       ppool);
#endif
}
