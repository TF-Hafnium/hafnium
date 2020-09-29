/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/spci.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

TEST_SERVICE(echo)
{
	/* Loop, echo messages back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		spci_vm_id_t target_vm_id = spci_msg_send_receiver(ret);
		spci_vm_id_t source_vm_id = spci_msg_send_sender(ret);
		void *send_buf = SERVICE_SEND_BUFFER();
		void *recv_buf = SERVICE_RECV_BUFFER();

		ASSERT_EQ(ret.func, SPCI_MSG_SEND_32);
		memcpy_s(send_buf, SPCI_MSG_PAYLOAD_MAX, recv_buf,
			 spci_msg_send_size(ret));

		EXPECT_EQ(spci_rx_release().func, SPCI_SUCCESS_32);
		spci_msg_send(target_vm_id, source_vm_id,
			      spci_msg_send_size(ret), 0);
	}
}
