/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/std.h"
#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/hftest_impl.h"
#include "test/vmapi/ffa.h"

/*
 * Secondary VM that loops forever after receiving a message.
 */

TEST_SERVICE(busy)
{
	char buffer[sizeof("loop")];
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_rxtx_header header;

	HFTEST_LOG("Secondary waiting for message...\n");
	mailbox_receive_retry(buffer, ARRAY_SIZE(buffer), recv_buf, &header);
	HFTEST_LOG("Secondary received message, looping forever.\n");
	for (;;) {
	}
}

TEST_SERVICE(busy_secondary_direct_message)
{
	struct ffa_value received;

	HFTEST_LOG("Secondary waiting for message...\n");
	received = ffa_msg_wait();
	EXPECT_EQ(received.func, FFA_MSG_SEND_DIRECT_REQ_32);

	HFTEST_LOG("Secondary received message, looping forever.\n");
	for (;;) {
	}
}
