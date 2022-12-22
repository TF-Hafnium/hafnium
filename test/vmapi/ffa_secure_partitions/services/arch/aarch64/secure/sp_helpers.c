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

static inline uint64_t virtualcounter_read(void)
{
	isb();
	return read_msr(cntvct_el0);
}

uint64_t sp_sleep_active_wait(uint32_t ms)
{
	uint64_t timer_freq = read_msr(cntfrq_el0);

	uint64_t time1 = virtualcounter_read();
	volatile uint64_t time2 = time1;

	while ((time2 - time1) < ((ms * timer_freq) / 1000U)) {
		time2 = virtualcounter_read();
	}

	return ((time2 - time1) * 1000) / timer_freq;
}

void sp_enable_irq(void)
{
	arch_irq_enable();
}

struct ffa_value handle_ffa_interrupt(struct ffa_value res)
{
	/*
	 * Received FFA_INTERRUPT in waiting state. The
	 * interrupt ID is passed although this is just
	 * informational as we're running with virtual
	 * interrupts unmasked and the interrupt is processed by
	 * the interrupt handler.
	 */
	ASSERT_EQ(res.arg1, 0);
	return ffa_msg_wait();
}

struct ffa_value handle_ffa_run(struct ffa_value res)
{
	/*
	 * Received FFA_RUN in waiting state, the endpoint
	 * simply returns by FFA_MSG_WAIT.
	 */
	ASSERT_EQ(res.arg1, 0);
	return ffa_msg_wait();
}
