/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

bool irq_current(void)
{
	return true;
}

bool sync_exception_current(void)
{
	return true;
}

void exception_setup(void (*irq)(void), bool (*exception)(void))
{
	(void)irq;
	(void)exception;
}

void interrupt_wait(void)
{
}

void arch_irq_enable(void)
{
}

void interrupts_enable(void)
{
}

void interrupts_disable(void)
{
}
