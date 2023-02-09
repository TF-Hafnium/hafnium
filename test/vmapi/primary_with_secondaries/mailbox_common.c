/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(mailbox)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Clearing an empty mailbox is an error.
 */
TEST(mailbox, clear_empty)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Send a message to relay_a which will forward it to relay_b where it will be
 * sent back here.
 */
TEST(mailbox, relay)
{
	const char message[] = "Send this round the relay!";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "relay", mb.send);
	SERVICE_SELECT(SERVICE_VM2, "relay", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);
	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/*
	 * Build the message chain so the message is sent from here to
	 * SERVICE_VM1, then to SERVICE_VM2 and finally back to here.
	 */
	{
		ffa_vm_id_t *chain = (ffa_vm_id_t *)mb.send;
		*chain++ = htole32(SERVICE_VM2);
		*chain++ = htole32(HF_PRIMARY_VM_ID);
		memcpy_s(chain, FFA_MSG_PAYLOAD_MAX - (2 * sizeof(ffa_vm_id_t)),
			 message, sizeof(message));

		EXPECT_EQ(
			ffa_msg_send(
				HF_PRIMARY_VM_ID, SERVICE_VM1,
				sizeof(message) + (2 * sizeof(ffa_vm_id_t)), 0)
				.func,
			FFA_SUCCESS_32);
	}

	/* Let SERVICE_VM1 forward the message. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);
	EXPECT_EQ(ffa_receiver(run_res), SERVICE_VM2);
	EXPECT_EQ(ffa_msg_send_size(run_res), 0);

	/* Let SERVICE_VM2 forward the message. */
	run_res = ffa_run(SERVICE_VM2, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_SEND_32);

	/* Ensure the message is intact. */
	EXPECT_EQ(ffa_receiver(run_res), HF_PRIMARY_VM_ID);
	EXPECT_EQ(ffa_msg_send_size(run_res), sizeof(message));
	EXPECT_EQ(memcmp(mb.recv, message, sizeof(message)), 0);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

/**
 * Send a message before the secondary VM is configured, but do not register
 * for notification. Ensure we're not notified.
 */
TEST(mailbox, no_primary_to_secondary_notification_on_configure)
{
	struct ffa_value run_res;

	set_up_mailbox();

	EXPECT_FFA_ERROR(ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 0, 0),
			 FFA_BUSY);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	EXPECT_EQ(ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 0, 0).func,
		  FFA_SUCCESS_32);
}
