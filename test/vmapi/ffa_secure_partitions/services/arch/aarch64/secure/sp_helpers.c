/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sp_helpers.h"

#include "hf/arch/barriers.h"
#include "hf/arch/irq.h"
#include "hf/arch/vm/timer.h"

#include "vmapi/hf/call.h"

#include "sp805.h"
#include "test/abort.h"
#include "test/hftest.h"

void sp_enable_irq(void)
{
	arch_irq_enable();
}

void sp_disable_irq(void)
{
	arch_irq_disable();
}

struct ffa_value handle_interrupt(struct ffa_value res)
{
	/*
	 * Received FFA_INTERRUPT in waiting state. The
	 * interrupt ID is passed although this is just
	 * informational as we're running with virtual
	 * interrupts unmasked and the interrupt is processed by
	 * the interrupt handler.
	 */
	ASSERT_EQ(res.arg1, 0);

	/* Unmask all virtual interrupts such that they are handled now. */
	sp_enable_irq();

	return ffa_msg_wait();
}
