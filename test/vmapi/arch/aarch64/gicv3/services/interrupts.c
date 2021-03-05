/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"

#include "hf/call.h"

#include "test/hftest.h"

/**
 * The secondary VM handles a direct message request, but it is interrupted
 * by a physical interrupt leading to a PVM switch before it can send a direct
 * message response. Once the PVM has handled the interrupt, it resumes the
 * secondary VM which can then send a direct message response.
 */
TEST_SERVICE(interrupts_secondary_direct_message)
{
	struct ffa_value res;

	arch_irq_enable();

	dlog("Secondary VM waits for a direct message request.\n");

	res = ffa_msg_wait();
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	/**
	 * At this stage the secondary VM is interrupted by an SGI routed to
	 * the PVM. Execution restarts from here after the PVM relinquishes
	 * CPU time through ffa_run.
	 */

	dlog("Secondary VM sends a direct message response.\n");
	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0, 0, 0,
				 0);
}
