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

bool arch_timer_enabled(struct arch_regs *regs)
{
	return regs->arch_timer.ctl == 1;
}

uint64_t arch_timer_remaining_ns(struct arch_regs *regs)
{
	/* For simplicity, we assume one tick is one nano second. */
	return regs->arch_timer.cval;
}

bool arch_timer_expired(struct arch_regs *regs)
{
	return regs->arch_timer.cval == 0;
}
