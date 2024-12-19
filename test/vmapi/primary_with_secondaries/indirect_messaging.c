/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

SET_UP(indirect_messaging_v1_1)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_1), FFA_VERSION_COMPILED);
}

SET_UP(indirect_messaging)
{
	/*
	 * Call FFA_VERSION to inform the hypervisor of the compiled FF-A
	 * Version.
	 */
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED), FFA_VERSION_COMPILED);
}

static bool v1_1_or_earlier(void)
{
	return FFA_VERSION_COMPILED <= FFA_VERSION_1_1;
}

/**
 * Send and receive the same message from the echo VM using
 * FFA v1.1 FFA_MSG_SEND2 ABI.
 */
TEST(indirect_messaging, echo)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const uint32_t payload = 0xAA55AA55;
	const uint32_t echo_payload;
	ffa_id_t echo_sender;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "echo_msg_send2", mb.send);

	/* Send the message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Schedule message receiver. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_indirect_message((void *)&echo_payload, sizeof(echo_payload),
				 mb.recv, &echo_sender);

	HFTEST_LOG("Message echoed back: %#x", echo_payload);
	EXPECT_EQ(echo_payload, payload);
	EXPECT_EQ(echo_sender, service1_info->vm_id);
}

/** Sender haven't mapped TX buffer. */
TEST_PRECONDITION(indirect_messaging, unmapped_tx, hypervisor_only)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const uint32_t payload = 0xAA55AA55;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_indirect_msg_error", mb.send);

	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);

	/* Send the message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	EXPECT_FFA_ERROR(ret, FFA_DENIED);
}

/** Receiver haven't mapped RX buffer. */
TEST(indirect_messaging, unmapped_rx)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const uint32_t payload = 0xAA55AA55;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_indirect_msg_error", mb.send);

	/* Schedule message receiver. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send the message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);
}

/** Receiver haven't read a previous message. */
TEST(indirect_messaging, unread_message)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const uint32_t payload = 0xAA55AA55;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_indirect_msg_error", mb.send);

	/* Send the message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Immediately send another message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);
}

/**
 * Send an indirect message (`FFA_MSG_SEND2`) and assert that it returned an
 * `FFA_INVALID_PARAMETERS` error.
 */
static void msg_send2_invalid_parameters(
	struct ffa_partition_rxtx_header header, struct mailbox_buffers mb)
{
	struct ffa_value ret;
	struct ffa_partition_msg *message;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_indirect_msg_error", mb.send);

	message = mb.send;
	message->header = header;

	/* The header is expected to be invalid, do not set any payload. */

	ret = ffa_msg_send2(0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

/**
 * Send an indirect message (`FFA_MSG_SEND2`) and assert that it succeeds.
 */
static void msg_send2_valid_parameters(struct ffa_partition_rxtx_header header,
				       struct mailbox_buffers mb)
{
	struct ffa_value ret;
	struct ffa_partition_msg *message;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_indirect_msg_error", mb.send);

	message = mb.send;
	message->header = header;

	ret = ffa_msg_send2(0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/** Sender sends message with a non existing VM IDs. */
TEST(indirect_messaging, non_existing_sender)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = service1_info->vm_id,
		.receiver = service2_info->vm_id,
	};

	msg_send2_invalid_parameters(header, mb);
}

/** Sender sends message with another sender VM IDs. */
TEST(indirect_messaging, corrupted_sender)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = service1_info->vm_id,
		.receiver = own_id,
	};

	msg_send2_invalid_parameters(header, mb);
}

/** Sender sends message to itself. */
TEST(indirect_messaging, self_message)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_rxtx_header header = {
		.sender = own_id,
		.receiver = own_id,
	};

	msg_send2_invalid_parameters(header, mb);
}

/** Sender sends message with invalid size. */
TEST(indirect_messaging, invalid_size)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = own_id,
		.receiver = service1_info->vm_id,
		.size = 1024 * 1024,
	};

	msg_send2_invalid_parameters(header, mb);
}

/**
 * v1.1 message where payload overlaps with the `payload.size` field should
 * fail.
 */
TEST(indirect_messaging_v1_1, payload_overlap)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = own_id,
		.receiver = service1_info->vm_id,
		.size = 1024,
		.offset = offsetof(struct ffa_partition_rxtx_header, size),
	};

	msg_send2_invalid_parameters(header, mb);
}

/**
 * v1.1 message with gap between the header and the payload should not fail.
 * This will fail for v1.2 or later.
 */
TEST_PRECONDITION(indirect_messaging_v1_1, payload_gap, v1_1_or_earlier)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = own_id,
		.receiver = service1_info->vm_id,
		.size = 1024,
		.offset = offsetof(struct ffa_partition_rxtx_header, uuid),
	};

	msg_send2_valid_parameters(header, mb);

	header.offset = offsetof(struct ffa_partition_rxtx_header, reserved_2);
	msg_send2_valid_parameters(header, mb);
}

/**
 * v1.2 message where payload overlaps with the `payload.size` or the
 * `payload.uuid` fields should fail.
 */
TEST(indirect_messaging_v1_2, payload_overlap)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = own_id,
		.receiver = service1_info->vm_id,
		.size = 1024,
		.offset = offsetof(struct ffa_partition_rxtx_header, size),
	};

	msg_send2_invalid_parameters(header, mb);
	header.offset = offsetof(struct ffa_partition_rxtx_header, uuid);
}

/**
 * v1.2 message where where `payload.offset + payload.size` overflows should
 * fail.
 */
TEST(indirect_messaging_v1_2, size_plus_offset_overflow)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_rxtx_header header = {
		.sender = own_id,
		.receiver = service1_info->vm_id,
		.size = -1,
		.offset = FFA_RXTX_HEADER_SIZE,
	};

	msg_send2_invalid_parameters(header, mb);
}

/**
 * First, service1 sends message to service2, which sends it back to service1.
 * After, PVM sends another message to service2, and see it echoes back
 * to the PVM.
 */
TEST(indirect_messaging, services_echo)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const struct ffa_uuid service2_uuid = SERVICE2;
	const ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;
	const uint32_t payload = 0xAA55AA55;
	uint32_t echo_payload;
	ffa_id_t echo_sender;

	SERVICE_SELECT(service1_info->vm_id, "echo_msg_send2_service", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "echo_msg_send2", mb.send);

	/* Send to service1 the uuid of the target for its message. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &service2_uuid, sizeof(service2_uuid), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	/* Run service1 to retrieve uuid of target, and send message. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Run service2 to echo message back to service1. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Run service1 to validate message received from service2. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/*
	 * Send another message to service2 and check that it echos back
	 * correctly.
	 */
	ret = send_indirect_message(own_id, service2_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	/* Run service2 to echo message back to PVM. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_indirect_message(&echo_payload, sizeof(echo_payload), mb.recv,
				 &echo_sender);

	HFTEST_LOG("Message received: %#x", echo_payload);

	EXPECT_EQ(echo_sender, service2_info->vm_id);
	EXPECT_EQ(echo_payload, payload);
}

TEAR_DOWN(indirect_messaging)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Clearing an empty mailbox is an error.
 */
TEST(indirect_messaging, clear_empty)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Send a message to relay_a which will forward it to relay_b where it will be
 * sent back here.
 */
TEST(indirect_messaging, relay)
{
	const char expected_message[] = "Send this round the relay!";
	const size_t message_size = sizeof(expected_message) + sizeof(ffa_id_t);
	char response[message_size];
	char message[message_size];
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_value ret;
	ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(service1_info->vm_id, "relay", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "relay", mb.send);

	/*
	 * Build the message chain so the message is sent from here to
	 * service1, then to service2 and finally back to here.
	 */
	{
		ffa_id_t *chain = (ffa_id_t *)message;
		*chain = htole32(service2_info->vm_id);

		memcpy_s(&message[sizeof(*chain)],
			 message_size - sizeof(ffa_id_t), expected_message,
			 sizeof(expected_message));

		ret = send_indirect_message(own_id, service1_info->vm_id,
					    mb.send, message, message_size, 0);
		EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	}

	/* Let service1 forward the message. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Let service2 forward the message. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Ensure the message is intact. */
	receive_indirect_message(response, sizeof(response), mb.recv, NULL);
	EXPECT_EQ(memcmp(&response[sizeof(ffa_id_t)], expected_message,
			 sizeof(expected_message)),
		  0);
}
