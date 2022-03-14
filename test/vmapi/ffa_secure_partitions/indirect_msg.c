/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/** Ask SP1 to send a message to SP2, which will echo it back to SP1. */
TEST(indirect_msg, echo_sp)
{
	const ffa_vm_id_t own_id = hf_vm_get_id();
	const ffa_vm_id_t receiver_id = SP_ID(1);
	const ffa_vm_id_t msg_receiver_id = SP_ID(2);
	const uint32_t payload = 0xAA55AA55;
	struct ffa_value ret;

	ret = sp_indirect_msg_cmd_send(own_id, receiver_id, msg_receiver_id,
				       payload);

	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);
}

/** VM1 sends a message to SP1, which will echo it back to VM1. */
TEST(indirect_msg, echo_cross_world)
{
	const ffa_vm_id_t own_id = hf_vm_get_id();
	const ffa_vm_id_t receiver_id = SP_ID(1);
	const uint32_t payload = 0xAA55AA55;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_msg *message;
	const uint32_t *echo_payload;
	struct ffa_value ret;

	ret = send_indirect_message(own_id, receiver_id, mb.send, &payload,
				    sizeof(payload), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Notify the receiver that got an indirect message. */
	ret = sp_echo_indirect_msg_cmd_send(own_id, receiver_id);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	/* Check notification. */
	ret = ffa_notification_get(own_id, 0, FFA_NOTIFICATION_FLAG_BITMAP_SPM);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ASSERT_TRUE(is_ffa_spm_buffer_full_notification(
		ffa_notification_get_from_framework(ret)));

	/* Ensure echoed message is the same as sent. */
	message = (struct ffa_partition_msg *)mb.recv;
	echo_payload = (const uint32_t *)message->payload;
	ASSERT_EQ(payload, *echo_payload);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}
