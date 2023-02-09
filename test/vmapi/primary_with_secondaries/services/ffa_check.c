/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Service for indirect message error checking.
 * The VM unmap its RX/TX and waits for a message.
 */
TEST_SERVICE(ffa_indirect_msg_error)
{
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);

	ffa_msg_wait();
}

/**
 * Service waits for a direct message request but primary VM
 * calls ffa_run instead. Verify the service does not run.
 */
TEST_SERVICE(ffa_direct_msg_run)
{
	struct ffa_value res = ffa_msg_wait();

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	res = ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0,
				       0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 3);

	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 4, 0, 0, 0,
				 0);
}
