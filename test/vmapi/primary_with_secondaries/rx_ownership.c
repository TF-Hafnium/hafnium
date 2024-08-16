/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Test to verify that when an SP calls FFA_MSG_WAIT, it relinquishes the
 * ownership of its RX buffer back to the SPMC. Test sequence is as follows:
 * 	1. PVM runs SP via FFA_RUN.
 * 	2. SP calls FFA_PARTITION_INFO_GET to gain ownership of its RX buffer
 * from the SPMC.
 * 	3. SP calls FFA_MSG_WAIT, relinquishing RX buffer to SPMC and control
 * back to PVM.
 * 	4. PVM sends SP an indirect message to fill the RX buffer and runs via
 * FFA_RUN.
 * 	5. SP  successfully receives indirect message, verifying the message
 * sent from the PVM.
 */
TEST_PRECONDITION(rx_ownership, ffa_msg_wait_buffer_full, service1_is_not_vm)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;
	uint64_t msg = 0x123;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "test_ffa_msg_wait_release_buffer",
		       mb.send);

	/* Run service to call FFA_PARTITION_INFO_GET, then FFA_MSG_WAIT. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Run service again after FFA_MSG_WAIT (which should have released
	 * the buffer). Sending an indirect message should succeed since buffer
	 * was released back to SPMC.
	 */
	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, &msg, sizeof(msg), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}
