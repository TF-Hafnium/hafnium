/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "../smc.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEST_SERVICE(sip_call_trigger_spi)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	uint32_t interrupt_id;

	/* Retrieve interrupt ID to be triggered. */
	receive_indirect_message((void *)&interrupt_id, sizeof(interrupt_id),
				 recv_buf, NULL);

	/*
	 * The SiP function ID 0x82000100 must have been added to the SMC
	 * whitelist of the SP that invokes it.
	 */
	res = smc32(0x82000100, interrupt_id, 0, 0, 0, 0, 0, 0);

	EXPECT_NE(res.func, SMCCC_ERROR_UNKNOWN);

	/* Give back control to PVM. */
	ffa_yield();
}
