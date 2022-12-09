/*
 * Copyright 2022 The Hafnium Authors.
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

SET_UP(indirect_messaging)
{
	/* Call FFA_VERSION to inform the hypervisor we are v1.1. */
	ffa_version(MAKE_FFA_VERSION(1, 1));
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
	ffa_vm_id_t echo_sender;
	ffa_vm_id_t own_id = hf_vm_get_id();
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
	ffa_vm_id_t own_id = hf_vm_get_id();
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
	ffa_vm_id_t own_id = hf_vm_get_id();
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
	ffa_vm_id_t own_id = hf_vm_get_id();
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

static void msg_send2_invalid_parameters(ffa_vm_id_t sender,
					 ffa_vm_id_t receiver, uint32_t size,
					 void *send, void *recv)
{
	struct ffa_value ret;
	struct ffa_partition_msg *message;
	struct ffa_partition_info *service1_info = service1(recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_indirect_msg_error", send);

	message = (struct ffa_partition_msg *)send;
	ffa_rxtx_header_init(sender, receiver, size, &message->header);

	/* The header is expected to be invalid, do not set any payload. */

	ret = ffa_msg_send2(0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

/** Sender sends message with a non existing VM IDs. */
TEST(indirect_messaging, non_existing_sender)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	msg_send2_invalid_parameters(service2_info->vm_id, service1_info->vm_id,
				     0, mb.send, mb.recv);
}

/** Sender sends message with another sender VM IDs. */
TEST(indirect_messaging, corrupted_sender)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	msg_send2_invalid_parameters(service1_info->vm_id, own_id, 0, mb.send,
				     mb.recv);
}

/** Sender sends message to itself. */
TEST(indirect_messaging, self_message)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_vm_id_t own_id = hf_vm_get_id();

	msg_send2_invalid_parameters(own_id, own_id, 0, mb.send, mb.recv);
}

/** Sender sends message with invalid size. */
TEST(indirect_messaging, invalid_size)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	msg_send2_invalid_parameters(own_id, service1_info->vm_id, 1024 * 1024,
				     mb.send, mb.recv);
}
