/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "common.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Try to receive a message from the mailbox, blocking if necessary, and
 * retrying if interrupted.
 */
void mailbox_receive_retry(void *buffer, size_t buffer_size, void *recv,
			   struct ffa_partition_rxtx_header *header)
{
	const struct ffa_partition_msg *message;
	const uint32_t *payload;
	ffa_vm_id_t sender;
	struct ffa_value ret;
	ffa_notifications_bitmap_t fwk_notif = 0U;
	const ffa_vm_id_t own_id = hf_vm_get_id();

	ASSERT_LE(buffer_size, FFA_MSG_PAYLOAD_MAX);
	ASSERT_TRUE(header != NULL);
	ASSERT_TRUE(recv != NULL);

	/* Check notification and wait if not messages. */
	while (fwk_notif == 0U) {
		ret = ffa_notification_get(
			own_id, 0,
			FFA_NOTIFICATION_FLAG_BITMAP_SPM |
				FFA_NOTIFICATION_FLAG_BITMAP_HYP);
		if (ret.func == FFA_SUCCESS_32) {
			fwk_notif = ffa_notification_get_from_framework(ret);
		}

		if (fwk_notif == 0U) {
			ffa_msg_wait();
		}
	}

	message = (const struct ffa_partition_msg *)recv;
	memcpy_s(header, sizeof(*header), message,
		 sizeof(struct ffa_partition_rxtx_header));

	sender = ffa_rxtx_header_sender(header);

	if (is_ffa_hyp_buffer_full_notification(fwk_notif)) {
		EXPECT_TRUE(IS_VM_ID(sender));
	} else {
		FAIL("Unexpected message sender.\n");
	}

	/* Check receiver ID against own ID. */
	ASSERT_EQ(ffa_rxtx_header_receiver(header), own_id);
	ASSERT_LE(header->size, buffer_size);

	payload = (const uint32_t *)message->payload;

	/* Get message to free the RX buffer. */
	memcpy_s(buffer, buffer_size, payload, header->size);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}
