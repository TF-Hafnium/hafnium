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

SET_UP(indirect_messaging_v1_0)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_0), FFA_VERSION_COMPILED);
}

SET_UP(indirect_messaging_v1_1)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_1), FFA_VERSION_COMPILED);
}

SET_UP(indirect_messaging_v1_2)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_2), FFA_VERSION_COMPILED);
}

SET_UP(indirect_messaging)
{
	/*
	 * Call FFA_VERSION to inform the hypervisor of the compiled FF-A
	 * Version.
	 */
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED), FFA_VERSION_COMPILED);
}

bool v1_0_or_earlier(void)
{
	return FFA_VERSION_COMPILED <= FFA_VERSION_1_0;
}

bool v1_1_or_earlier(void)
{
	return FFA_VERSION_COMPILED <= FFA_VERSION_1_1;
}

void indirect_messaging_test(struct mailbox_buffers mb, ffa_id_t receiver,
			     enum ffa_version sender_version,
			     enum ffa_version receiver_version,
			     struct ffa_uuid send_uuid,
			     struct ffa_uuid expected_uuid)
{
	ffa_id_t sender = hf_vm_get_id();
	const char send_payload[255] = "hello world";
	char recv_payload[255] = {0};
	struct ffa_value ret;

	struct ffa_partition_rxtx_header recv_header;

	if (receiver_version >= FFA_VERSION_1_2) {
		SERVICE_SELECT(receiver, "echo_msg_send2_v1_2", mb.send);
	} else {
		SERVICE_SELECT(receiver, "echo_msg_send2_v1_1", mb.send);
	}

	if (sender_version >= FFA_VERSION_1_2) {
		ret = send_indirect_message_with_uuid(
			sender, receiver, mb.send, &send_payload,
			sizeof(send_payload), send_uuid, 0);
	} else {
		ret = send_indirect_message_v1_1(sender, receiver, mb.send,
						 &send_payload,
						 sizeof(send_payload), 0);
	}
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(receiver, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	recv_header = receive_indirect_message(&recv_payload,
					       sizeof(recv_payload), mb.recv);

	if (receiver_version >= FFA_VERSION_1_2) {
		for (size_t i = 0; i < 4; i++) {
			EXPECT_EQ(recv_header.uuid.uuid[i],
				  expected_uuid.uuid[i]);
		}
	}

	EXPECT_STREQ(recv_payload, send_payload);
	EXPECT_EQ(recv_header.receiver, sender);
	EXPECT_EQ(recv_header.sender, receiver);
}

/**
 * A v1.0 sender should get an `FFA_NOT_SUPPORTED` error.
 */
TEST_PRECONDITION(indirect_messaging_v1_0, v1_0_not_supported, hypervisor_only)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const char payload[255] = "hello world";
	ffa_id_t sender = hf_vm_get_id();
	ffa_id_t receiver = service1(mb.recv)->vm_id;

	EXPECT_EQ(ffa_is_vm_id(receiver), true);
	ret = ffa_run(receiver, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(ret.arg2, FFA_SLEEP_INDEFINITE);

	ret = send_indirect_message(sender, receiver, mb.send, &payload,
				    sizeof(payload), 0);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);
}

/**
 * Send a v1.1 message to a v1.1 receiver. UUID should be zeroed.
 */
TEST_PRECONDITION(indirect_messaging_v1_1, echo_v1_1_to_v1_1, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t receiver = service3(mb.recv)->vm_id;

	indirect_messaging_test(mb, receiver, FFA_VERSION_1_1, FFA_VERSION_1_1,
				(struct ffa_uuid){0}, (struct ffa_uuid){0});
}

/**
 * Send a v1.1 message to a v1.2 receiver. UUID should be zeroed.
 */
TEST_PRECONDITION(indirect_messaging_v1_1, echo_v1_1_to_v1_2, hypervisor_only)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t receiver = service1(mb.recv)->vm_id;

	indirect_messaging_test(mb, receiver, FFA_VERSION_1_1, FFA_VERSION_1_2,
				(struct ffa_uuid){0}, (struct ffa_uuid){0});
}

/**
 * Send a v1.2 message to a v1.2 receiver. UUID should be preserved.
 */
TEST(indirect_messaging_v1_2, echo_v1_2_to_v1_2)
{
	struct ffa_uuid uuid = {
		0xAAAAAAAA,
		0xBBBBBBBB,
		0xCCCCCCCC,
		0xDDDDDDDD,
	};
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t receiver = service1(mb.recv)->vm_id;

	indirect_messaging_test(mb, receiver, FFA_VERSION_1_2, FFA_VERSION_1_2,
				uuid, uuid);
}

/**
 * Send a v1.2 message to a v1.1 receiver. UUID should be dropped.
 */
TEST_PRECONDITION(indirect_messaging_v1_2, echo_v1_2_to_v1_1, hypervisor_only)
{
	struct ffa_uuid uuid = {
		0xAAAAAAAA,
		0xBBBBBBBB,
		0xCCCCCCCC,
		0xDDDDDDDD,
	};
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t receiver = service3(mb.recv)->vm_id;

	indirect_messaging_test(mb, receiver, FFA_VERSION_1_2, FFA_VERSION_1_1,
				uuid, uuid);
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
	const char payload[255] = "hello from v1.2";
	char echo_payload[255] = {0};
	ffa_id_t echo_sender;

	SERVICE_SELECT(service1_info->vm_id, "echo_msg_send2_service", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "echo_msg_send2_v1_2", mb.send);

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
				    payload, sizeof(payload), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	/* Run service2 to echo message back to PVM. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	echo_sender = receive_indirect_message(echo_payload,
					       sizeof(echo_payload), mb.recv)
			      .sender;

	HFTEST_LOG("Message received: %s", echo_payload);

	EXPECT_EQ(echo_sender, service2_info->vm_id);
	EXPECT_STREQ(echo_payload, payload);
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
	receive_indirect_message(response, sizeof(response), mb.recv);
	EXPECT_EQ(memcmp(&response[sizeof(ffa_id_t)], expected_message,
			 sizeof(expected_message)),
		  0);
}
