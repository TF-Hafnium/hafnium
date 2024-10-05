/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/timer.h"

#include <stdbool.h>
#include <stdint.h>

#include "hf/arch/types.h"

bool arch_timer_pending(struct arch_regs *regs)
{
	/* TODO */
	(void)regs;
	return false;
}

void arch_timer_mask(struct arch_regs *regs)
{
	/* TODO */
	(void)regs;
}

bool arch_timer_enabled(struct arch_regs *regs)
{
	/* TODO */
	(void)regs;
	return false;
}

uint64_t arch_timer_remaining_ns(struct arch_regs *regs)
{
	/* TODO */
	(void)regs;
	return 0;
}
