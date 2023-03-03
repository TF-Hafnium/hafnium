/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdbool.h>

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/exception_handler.h"
#include "test/vmapi/ffa.h"

static void check_npi(void)
{
	ASSERT_EQ(hf_interrupt_get(), HF_NOTIFICATION_PENDING_INTID);
	HFTEST_LOG("Received notification pending interrupt.");
}

TEST_SERVICE(echo)
{
	/* Loop, echo messages back to the sender. */
	for (;;) {
		struct ffa_value ret = ffa_msg_wait();
		ffa_vm_id_t target_vm_id = ffa_receiver(ret);
		ffa_vm_id_t source_vm_id = ffa_sender(ret);
		void *send_buf = SERVICE_SEND_BUFFER();
		void *recv_buf = SERVICE_RECV_BUFFER();

		ASSERT_EQ(ret.func, FFA_MSG_SEND_32);
		memcpy_s(send_buf, FFA_MSG_PAYLOAD_MAX, recv_buf,
			 ffa_msg_send_size(ret));

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
		ffa_msg_send(target_vm_id, source_vm_id, ffa_msg_send_size(ret),
			     0);
	}
}

TEST_SERVICE(echo_msg_send2)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();

	/* Setup handling of NPI, to handle RX buffer full notification. */
	exception_setup(check_npi, NULL);
	arch_irq_enable();

	for (;;) {
		uint32_t payload;
		ffa_vm_id_t echo_sender;

		receive_indirect_message((void *)&payload, sizeof(payload),
					 recv_buf, &echo_sender);

		HFTEST_LOG("Message received: %#x", payload);

		/* Echo message back. */
		send_indirect_message(hf_vm_get_id(), echo_sender, send_buf,
				      &payload, sizeof(payload), 0);

		/* Give back control to PVM. */
		ffa_yield();
	}
}

TEST_SERVICE(echo_msg_send2_release_msg_wait)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();

	/* Setup handling of NPI, to handle RX buffer full notification. */
	exception_setup(check_npi, NULL);
	arch_irq_enable();

	for (;;) {
		uint32_t payload;
		ffa_vm_id_t echo_sender;

		receive_indirect_message_release((void *)&payload,
						 sizeof(payload), recv_buf,
						 &echo_sender, false);

		HFTEST_LOG("Message received: %#x", payload);

		/* Echo message back. */
		send_indirect_message(hf_vm_get_id(), echo_sender, send_buf,
				      &payload, sizeof(payload), 0);

		/* This is when the buffer is expected to have been released. */
		ffa_msg_wait();
	}
}

TEST_SERVICE(echo_msg_send2_service)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_uuid target_uuid;
	struct ffa_partition_info target_info;
	uint32_t echo_payload;
	ffa_vm_id_t echo_sender;
	const uint32_t payload = 0xBEEFU;
	struct ffa_value ret;
	const ffa_vm_id_t own_id = hf_vm_get_id();

	/* Setup handling of NPI, to handle RX buffer notification. */
	exception_setup(check_npi, NULL);
	arch_irq_enable();

	/* Retrieve uuid of target endpoint. */
	receive_indirect_message((void *)&target_uuid, sizeof(target_uuid),
				 recv_buf, NULL);

	/* From uuid to respective partition info. */
	ASSERT_EQ(get_ffa_partition_info(&target_uuid, &target_info,
					 sizeof(target_info), recv_buf),
		  1);

	/* Send message to target. */
	ret = send_indirect_message(own_id, target_info.vm_id, send_buf,
				    &payload, sizeof(payload), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ffa_yield();

	receive_indirect_message(&echo_payload, sizeof(echo_payload), recv_buf,
				 &echo_sender);

	HFTEST_LOG("Message received: %#x", echo_payload);

	EXPECT_EQ(echo_sender, target_info.vm_id);

	/* Give back control to caller VM. */
	ffa_yield();
}
