/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include <stdint.h>

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Send a message to a secondary VM which checks the validity of the received
 * header.
 */
TEST(ffa, msg_send)
{
	const char message[] = "ffa_msg_send";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_check", mb.send);

	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_EQ(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		FFA_SUCCESS_32);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Send a message to a secondary VM spoofing the source VM id.
 */
TEST(ffa, msg_send_spoof)
{
	const char message[] = "ffa_msg_send";
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_check", mb.send);

	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_FFA_ERROR(
		ffa_msg_send(SERVICE_VM2, SERVICE_VM1, sizeof(message), 0),
		FFA_INVALID_PARAMETERS);
}

/**
 * Send a message to a secondary VM with incorrect destination id.
 */
TEST(ffa, ffa_invalid_destination_id)
{
	const char message[] = "fail to send";
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_check", mb.send);
	/* Set the payload, init the message header and send the message. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_FFA_ERROR(ffa_msg_send(HF_PRIMARY_VM_ID, -1, sizeof(message), 0),
			 FFA_INVALID_PARAMETERS);
}

/**
 * Ensure that the length parameter is respected when sending messages.
 */
TEST(ffa, ffa_incorrect_length)
{
	const char message[] = "this should be truncated";
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_length", mb.send);

	/* Send the message and compare if truncated. */
	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	/* Hard code incorrect length. */
	EXPECT_EQ(ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 16, 0).func,
		  FFA_SUCCESS_32);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Attempt to send a message larger than what is supported.
 */
TEST(ffa, ffa_large_message)
{
	const char message[] = "fail to send";
	struct mailbox_buffers mb = set_up_mailbox();

	memcpy_s(mb.send, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	/* Send a message that is larger than the mailbox supports (4KB). */
	EXPECT_FFA_ERROR(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, 4 * 1024 + 1, 0),
		FFA_INVALID_PARAMETERS);
}

/**
 * Verify secondary VM non blocking recv.
 */
TEST(ffa, ffa_recv_non_blocking)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value run_res;

	/* Check is performed in secondary VM. */
	SERVICE_SELECT(SERVICE_VM1, "ffa_recv_non_blocking", mb.send);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Verify that partition discovery via the FFA_PARTITION_INFO interface
 * returns the expected information on the VMs in the system.
 */
TEST(ffa, ffa_partition_info)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;
	const struct ffa_partition_info *partitions = mb.recv;
	struct ffa_uuid uuid;
	ffa_vm_count_t vm_count;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	vm_count = ret.arg2;
	EXPECT_EQ(vm_count, 4);

	for (uint16_t index = 0; index < vm_count; ++index) {
		ffa_vm_id_t vm_id = partitions[index].vm_id;
		EXPECT_GE(vm_id, (ffa_vm_id_t)HF_PRIMARY_VM_ID);
		EXPECT_LE(vm_id, (ffa_vm_id_t)SERVICE_VM3);

		/*
		 * NOTE: The ordering is NOT specified by the spec, but is an
		 * artifact of how it's implemented in Hafnium. If that changes
		 * the following EXPECT could fail.
		 */
		EXPECT_EQ(vm_id, index + 1);

		EXPECT_GE(partitions[index].vcpu_count, 1);
	}

	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Trying to run a partition which is waiting for a message should not actually
 * run it, but return FFA_MSG_WAIT again.
 */
TEST(ffa, run_waiting)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value run_res;

	SERVICE_SELECT(SERVICE_VM1, "run_waiting", mb.send);

	/* Let the secondary get started and wait for a message. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/*
	 * Trying to run it again should return the same value, and not actually
	 * run it.
	 */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);
}

/**
 * Send direct message, verify that sent info is echoed back.
 */
TEST(ffa, ffa_send_direct_message_req_echo)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_direct_message_resp_echo", mb.send);
	ffa_run(SERVICE_VM1, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg3, msg[0]);
	EXPECT_EQ(res.arg4, msg[1]);
	EXPECT_EQ(res.arg5, msg[2]);
	EXPECT_EQ(res.arg6, msg[3]);
	EXPECT_EQ(res.arg7, msg[4]);
}

/**
 * Send direct message, secondary verifies disallowed SMC invocations while
 * ffa_msg_send_direct_req is being serviced.
 */
TEST(ffa, ffa_send_direct_message_req_disallowed_smc)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_direct_msg_req_disallowed_smc",
		       mb.send);
	ffa_run(SERVICE_VM1, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Send direct message to invalid destination.
 */
TEST(ffa, ffa_send_direct_message_req_invalid_dst)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct ffa_value res;

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, HF_PRIMARY_VM_ID,
				      msg[0], msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Verify that the primary VM can't send direct message responses.
 */
TEST(ffa, ffa_send_direct_message_resp_invalid)
{
	struct ffa_value res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "ffa_direct_message_resp_echo", mb.send);
	ffa_run(SERVICE_VM1, 0);

	res = ffa_msg_send_direct_resp(HF_PRIMARY_VM_ID, SERVICE_VM1, 0, 0, 0,
				       0, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Run secondary VM through ffa_run and check it cannot invoke
 * a direct message request.
 */
TEST(ffa, ffa_secondary_direct_msg_req_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_disallowed_direct_msg_req", mb.send);
	ffa_run(SERVICE_VM1, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 0, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Run secondary VM without sending a direct message request beforehand.
 * Secondary VM must fail sending a direct message response.
 */
TEST(ffa, ffa_secondary_direct_msg_resp_invalid)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_disallowed_direct_msg_resp", mb.send);
	ffa_run(SERVICE_VM1, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 0, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/**
 * Run secondary VM and send a direct message request. Secondary VM attempts
 * altering the sender and receiver in its direct message responses, and must
 * fail to do so.
 */
TEST(ffa, ffa_secondary_spoofed_response)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1,
		       "ffa_direct_msg_resp_invalid_sender_receiver", mb.send);
	ffa_run(SERVICE_VM1, 0);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 0, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
}

/*
 * The secondary vCPU is waiting for a direct request, but the primary instead
 * calls `FFA_RUN`. This should return immediately to the primary without the
 * secondary ever actually being run.
 */
TEST(ffa, ffa_secondary_run)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "ffa_direct_msg_run", mb.send);
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 2);

	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 3, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 4);
}
