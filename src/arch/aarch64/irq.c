/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"

void arch_irq_disable(void)
{
	__asm__ volatile("msr DAIFSet, #0xf");
}

void arch_irq_enable(void)
{
	__asm__ volatile("msr DAIFClr, #0xf");
}
