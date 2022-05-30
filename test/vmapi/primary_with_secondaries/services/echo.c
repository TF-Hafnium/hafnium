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
	const struct ffa_partition_msg *message;
	ffa_vm_id_t target_vm_id;
	ffa_vm_id_t source_vm_id;
	const uint32_t *payload;
	struct ffa_value ret;

	/* Check notification */
	ret = ffa_notification_get(hf_vm_get_id(), 0,
				   FFA_NOTIFICATION_FLAG_BITMAP_HYP);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ASSERT_TRUE(is_ffa_hyp_buffer_full_notification(
		ffa_notification_get_from_framework(ret)));

	message = (const struct ffa_partition_msg *)recv_buf;
	source_vm_id = ffa_rxtx_header_sender(&message->header);
	target_vm_id = ffa_rxtx_header_receiver(&message->header);
	payload = (const uint32_t *)message->payload;
	HFTEST_LOG("Message got: %#x", *payload);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Echo message back. */
	send_indirect_message(target_vm_id, source_vm_id, send_buf, payload,
			      sizeof(*payload), 0);

	/* Give back control to caller VM. */
	ffa_yield();
}
