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

#include "hf/spci.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "hftest.h"

TEST_SERVICE(echo)
{
	/* Loop, echo messages back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		spci_vm_id_t target_vm_id = spci_msg_send_receiver(ret);
		spci_vm_id_t source_vm_id = spci_msg_send_sender(ret);
		struct spci_message *send_buf = SERVICE_SEND_BUFFER();
		struct spci_message *recv_buf = SERVICE_RECV_BUFFER();

		ASSERT_EQ(ret.func, SPCI_MSG_SEND_32);
		memcpy_s(send_buf->payload, SPCI_MSG_PAYLOAD_MAX,
			 recv_buf->payload, spci_msg_send_size(ret));
		spci_message_init(SERVICE_SEND_BUFFER(),
				  spci_msg_send_size(ret), source_vm_id,
				  target_vm_id);

		hf_mailbox_clear();
		spci_msg_send(0);
	}
}
