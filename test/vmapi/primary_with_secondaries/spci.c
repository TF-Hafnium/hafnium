/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/spci.h"

#include <stdint.h>

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/spci.h"

/**
 * Send a message to a secondary VM which checks the validity of the received
 * header.
 */
TEST(spci, msg_send)
{
	const char message[] = "spci_msg_send";
	struct spci_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "spci_check", mb.send);

	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, SPCI_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_EQ(
		spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		SPCI_SUCCESS_32);

	run_res = spci_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, SPCI_YIELD_32);
}

/**
 * Send a message to a secondary VM spoofing the source VM id.
 */
TEST(spci, msg_send_spoof)
{
	const char message[] = "spci_msg_send";
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "spci_check", mb.send);

	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, SPCI_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_SPCI_ERROR(
		spci_msg_send(SERVICE_VM2, SERVICE_VM1, sizeof(message), 0),
		SPCI_INVALID_PARAMETERS);
}

/**
 * Send a message to a secondary VM with incorrect destination id.
 */
TEST(spci, spci_invalid_destination_id)
{
	const char message[] = "fail to send";
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "spci_check", mb.send);
	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, SPCI_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_SPCI_ERROR(
		spci_msg_send(HF_PRIMARY_VM_ID, -1, sizeof(message), 0),
		SPCI_INVALID_PARAMETERS);
}

/**
 * Ensure that the length parameter is respected when sending messages.
 */
TEST(spci, spci_incorrect_length)
{
	const char message[] = "this should be truncated";
	struct spci_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "spci_length", mb.send);

	/* Send the message and compare if truncated. */
	memcpy_s(mb.send, SPCI_MSG_PAYLOAD_MAX, message, sizeof(message));
	/* Hard code incorrect length. */
	EXPECT_EQ(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 16, 0).func,
		  SPCI_SUCCESS_32);
	run_res = spci_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, SPCI_YIELD_32);
}

/**
 * Attempt to send a message larger than what is supported.
 */
TEST(spci, spci_large_message)
{
	const char message[] = "fail to send";
	struct mailbox_buffers mb = set_up_mailbox();

	memcpy_s(mb.send, SPCI_MSG_PAYLOAD_MAX, message, sizeof(message));
	/* Send a message that is larger than the mailbox supports (4KB). */
	EXPECT_SPCI_ERROR(
		spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 4 * 1024 + 1, 0),
		SPCI_INVALID_PARAMETERS);
}

/**
 * Verify secondary VM non blocking recv.
 */
TEST(spci, spci_recv_non_blocking)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct spci_value run_res;

	/* Check is performed in secondary VM. */
	SERVICE_SELECT(SERVICE_VM1, "spci_recv_non_blocking", mb.send);
	run_res = spci_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, SPCI_YIELD_32);
}

/**
 * Send direct message, verify that sent info is echoed back.
 */
TEST(spci, spci_send_direct_message_req_echo)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct spci_value res;

	SERVICE_SELECT(SERVICE_VM1, "spci_direct_message_resp_echo", mb.send);
	spci_run(SERVICE_VM1, 0);

	res = spci_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, msg[0],
				       msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, SPCI_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);
}

/**
 * Send direct message, secondary verifies unallowed smc invocations while
 * spci_msg_send_direct_req is being serviced.
 */
TEST(spci, spci_send_direct_message_req_unallowed_smc)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct spci_value res;

	SERVICE_SELECT(SERVICE_VM1, "spci_direct_unallowed_smc", mb.send);
	spci_run(SERVICE_VM1, 0);

	res = spci_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, msg[0],
				       msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, SPCI_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Send direct message to invalid destination.
 */
TEST(spci, spci_send_direct_message_req_invalid_dst)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct spci_value res;

	res = spci_msg_send_direct_req(HF_PRIMARY_VM_ID, HF_PRIMARY_VM_ID,
				       msg[0], msg[1], msg[2], msg[3], msg[4]);

	EXPECT_SPCI_ERROR(res, SPCI_INVALID_PARAMETERS);
}

/*
 * Retrieve partition information for the primary VM.
 */
TEST(spci, spci_partition_info_get_primary)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t uuid[4] = {1};

	struct spci_value ret = spci_partition_info_get(uuid);
	EXPECT_EQ(ret.func, SPCI_SUCCESS_32);
	EXPECT_EQ(ret.arg2, 1);

	/* Check our data structure in the RX buffer. */
	struct spci_partition_info *info =
		(struct spci_partition_info *)mb.recv;
	EXPECT_EQ(info[0].id, HF_PRIMARY_VM_ID);
	EXPECT_EQ(info[0].execution_context, 8);
	EXPECT_EQ(info[0].partition_properties, 0x4);
}

/**
 * Retrieve partition information for a secondary VM.
 */
TEST(spci, spci_partition_info_get_secondary)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t uuid[4] = {2};

	struct spci_value ret = spci_partition_info_get(uuid);
	EXPECT_EQ(ret.func, SPCI_SUCCESS_32);
	EXPECT_EQ(ret.arg2, 1);

	/* Check our data structure in the RX buffer. */
	struct spci_partition_info *info =
		(struct spci_partition_info *)mb.recv;
	EXPECT_EQ(info[0].id, SERVICE_VM1);
	EXPECT_EQ(info[0].execution_context, 1);
	EXPECT_EQ(info[0].partition_properties, 0x4);
}

/**
 * Retrieve partition information for all VMs with the NULL UUID.
 */
TEST(spci, spci_partition_info_get_all)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t uuid[4] = {0};

	struct spci_value ret = spci_partition_info_get(uuid);
	EXPECT_EQ(ret.func, SPCI_SUCCESS_32);
	EXPECT_EQ(ret.arg2, 4);

	/* Check our data structure in the RX buffer. */
	struct spci_partition_info *info =
		(struct spci_partition_info *)mb.recv;
	EXPECT_EQ(info[0].id, HF_PRIMARY_VM_ID);
	EXPECT_EQ(info[0].execution_context, 8);
	EXPECT_EQ(info[0].partition_properties, 0x4);

	EXPECT_EQ(info[1].id, SERVICE_VM1);
	EXPECT_EQ(info[1].execution_context, 1);
	EXPECT_EQ(info[1].partition_properties, 0x4);

	EXPECT_EQ(info[2].id, SERVICE_VM2);
	EXPECT_EQ(info[2].execution_context, 1);
	EXPECT_EQ(info[2].partition_properties, 0x4);

	EXPECT_EQ(info[3].id, SERVICE_VM3);
	EXPECT_EQ(info[3].execution_context, 2);
	EXPECT_EQ(info[3].partition_properties, 0x4);
}

/**
 *Attempt to retrive information for a non present UUID.
 */
TEST(spci, spci_partition_info_get_none)
{
	uint32_t uuid[4] = {42};

	EXPECT_SPCI_ERROR(spci_partition_info_get(uuid),
			  SPCI_INVALID_PARAMETERS);
}
