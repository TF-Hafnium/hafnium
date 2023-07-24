/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/interrupts.h"
#include "hf/types.h"

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
	(void)min_priority;
}

uint8_t plat_interrupts_get_priority_mask(void)
{
	return 0;
}

void plat_interrupts_set_priority(uint32_t id, uint32_t core_pos,
				  uint32_t priority)
{
	(void)id;
	(void)core_pos;
	(void)priority;
}

void plat_interrupts_disable(uint32_t id, uint32_t core_pos)
{
	(void)id;
	(void)core_pos;
}

void plat_interrupts_set_type(uint32_t id, uint32_t type)
{
	(void)id;
	(void)type;
}

uint32_t plat_interrupts_get_type(uint32_t id)
{
	(void)id;
	return 0;
}

uint32_t plat_interrupts_get_pending_interrupt_id(void)
{
	return 0;
}

void plat_interrupts_end_of_interrupt(uint32_t id)
{
	(void)id;
}

void plat_interrupts_configure_interrupt(struct interrupt_descriptor int_desc)
{
	(void)int_desc;
}

void plat_interrupts_send_sgi(uint32_t id, struct cpu *cpu,
			      bool to_this_security_state)
{
	(void)id;
	(void)cpu;
	(void)to_this_security_state;
}

void plat_interrupts_reconfigure_interrupt(struct interrupt_descriptor int_desc)
{
	(void)int_desc;
}
