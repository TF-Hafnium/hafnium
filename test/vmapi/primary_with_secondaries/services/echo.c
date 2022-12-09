/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEST_SERVICE(echo)
{
	/* Loop, echo messages back to the sender. */
	for (;;) {
		struct ffa_value ret = ffa_msg_wait();
		ffa_vm_id_t target_vm_id = ffa_receiver(ret);
		ffa_vm_id_t source_vm_id = ffa_sender(ret);
		void *send_buf = SERVICE_SEND_BUFFER();
		void *recv_buf = SERVICE_RECV_BUFFER();

		ASSERT_EQ(ret.func, FFA_MSG_SEND_32);
		memcpy_s(send_buf, FFA_MSG_PAYLOAD_MAX, recv_buf,
			 ffa_msg_send_size(ret));

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
		ffa_msg_send(target_vm_id, source_vm_id, ffa_msg_send_size(ret),
			     0);
	}
}

TEST_SERVICE(echo_msg_send2)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	uint32_t payload;
	ffa_vm_id_t echo_sender;

	receive_indirect_message((void *)&payload, sizeof(payload), recv_buf,
				 &echo_sender);

	HFTEST_LOG("Message received: %#x", payload);

	/* Echo message back. */
	send_indirect_message(hf_vm_get_id(), echo_sender, send_buf, &payload,
			      sizeof(payload), 0);

	/* Give back control to caller VM. */
	ffa_yield();
}
