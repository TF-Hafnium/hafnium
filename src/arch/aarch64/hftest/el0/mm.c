/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/mm.h"

#include "hf/arch/mm.h"

#include "hf/mm.h"

/**
 * MM support is not done at EL0.
 * Define dummy functions for EL0 targets.
 */
bool arch_vm_mm_init(void)
{
	return true;
}

void arch_vm_mm_enable(const struct mm_ptable *ptable)
{
	(void)ptable;
}

void arch_vm_mm_reset(void)
{
}

mm_mode_t arch_mm_extra_mode_from_vm(ffa_id_t id)
{
	(void)id;
	return 0;
}
