/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

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
		const char expected_message[] = "Send this round the relay!";
		ffa_id_t *chain;
		ffa_id_t next_id;
		void *next_message;
		uint8_t message[sizeof(expected_message) + sizeof(ffa_id_t)];
		ffa_id_t sender;
		ffa_id_t own_id = hf_vm_get_id();
		/* Prepare to relay the message. */
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();

		receive_indirect_message(message, sizeof(message), recv_buf,
					 &sender);

		chain = (ffa_id_t *)message;
		next_id = le16toh(*chain);
		next_message = &message[sizeof(*chain)];

		/* Check expected message is the same received message. */
		ASSERT_EQ(memcmp(expected_message, next_message,
				 sizeof(expected_message)),
			  0);

		/*
		 * Tell next partition to send message to sender, for full
		 * circle.
		 */
		*chain = sender;

		/* Send the message to the next stage. */
		send_indirect_message(own_id, next_id, send_buf, message,
				      sizeof(message), 0);
		ffa_yield();
	}
}
