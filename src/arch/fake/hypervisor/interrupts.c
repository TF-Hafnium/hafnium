/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/interrupts.h"

#include "hf/cpu.h"
#include "hf/ffa.h"

void plat_interrupts_set_priority_mask(uint8_t min_priority)
{
	(void)min_priority;
}

void plat_interrupts_controller_hw_init(struct cpu *c)
{
	(void)c;
}
