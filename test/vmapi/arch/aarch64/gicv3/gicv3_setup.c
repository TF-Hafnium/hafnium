/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/dlog.h"
#include "hf/mm.h"

#include "test/hftest.h"

volatile uint32_t last_interrupt_id = 0;

static void irq(void)
{
	uint32_t interrupt_id = interrupt_get_and_acknowledge();
	HFTEST_LOG("primary IRQ %d from current\n", interrupt_id);
	last_interrupt_id = interrupt_id;
	interrupt_end(interrupt_id);
	HFTEST_LOG("primary IRQ %d ended\n", interrupt_id);
}

void gicv3_system_setup(void)
{
	const uint32_t mode = MM_MODE_R | MM_MODE_W | MM_MODE_D;
	hftest_mm_identity_map((void *)GICD_BASE, PAGE_SIZE, mode);
	hftest_mm_identity_map((void *)GICR_BASE, PAGE_SIZE, mode);
	hftest_mm_identity_map((void *)IO32_C(SGI_BASE).ptr, PAGE_SIZE, mode);

	exception_setup(irq, NULL);
	interrupt_gic_setup();
}
