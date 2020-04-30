/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

TEST_SERVICE(relay)
{
	/*
	 * Loop, forward messages to the next VM.
	 *
	 * The first 32-bits of the message are the little-endian 32-bit ID of
	 * the VM to forward the message to. This ID will be dropped from the
	 * message so multiple IDs can be places at the start of the message.
	 */
	for (;;) {
		ffa_vm_id_t *chain;
		ffa_vm_id_t next_vm_id;
		void *next_message;
		uint32_t next_message_size;

		/* Receive the message to relay. */
		struct ffa_value ret = ffa_msg_wait();
		ASSERT_EQ(ret.func, FFA_MSG_SEND_32);

		/* Prepare to relay the message. */
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		ASSERT_GE(ffa_msg_send_size(ret), sizeof(ffa_vm_id_t));

		chain = (ffa_vm_id_t *)recv_buf;
		next_vm_id = le16toh(*chain);
		next_message = chain + 1;
		next_message_size =
			ffa_msg_send_size(ret) - sizeof(ffa_vm_id_t);

		/* Send the message to the next stage. */
		memcpy_s(send_buf, FFA_MSG_PAYLOAD_MAX, next_message,
			 next_message_size);

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
		ffa_msg_send(hf_vm_get_id(), next_vm_id, next_message_size, 0);
	}
}
