/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/interrupts.h"
#include "hf/types.h"

#include "msr.h"

bool plat_interrupts_controller_driver_init(
	const struct fdt *fdt, struct mm_stage1_locked stage1_locked,
	struct mpool *ppool)
{
	(void)fdt;
	(void)stage1_locked;
	(void)ppool;
	return true;
}

void plat_interrupts_controller_hw_init(struct cpu *c)
{
	(void)c;
}

void plat_interrupts_set_priority_mask(uint8_t min_priority)
{
	write_msr(ICC_PMR_EL1, min_priority);
}

void plat_interrupts_configure_interrupt(struct interrupt_descriptor int_desc)
{
	(void)int_desc;
}
