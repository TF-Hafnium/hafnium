/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "partition_services.h"

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

extern bool sel1_secure_service;

struct ffa_value sp_echo_cmd(ffa_vm_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	return ffa_msg_send_direct_resp(own_id, receiver, val1, val2, val3,
					val4, val5);
}

struct ffa_value sp_req_echo_cmd(ffa_vm_id_t test_source, uint32_t val1,
				 uint32_t val2, uint32_t val3, uint32_t val4)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, own_id + 1, val1, val2, val3, val4);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, val1);
	EXPECT_EQ(res.arg5, val2);
	EXPECT_EQ(res.arg6, val3);
	EXPECT_EQ(res.arg7, val4);

	return sp_success(own_id, test_source, 0);
}

struct ffa_value sp_req_echo_busy_cmd(ffa_vm_id_t test_source)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	if (IS_SP_ID(test_source)) {
		res = ffa_msg_send_direct_req(own_id, test_source, 0, 0, 0, 0,
					      0);
		EXPECT_FFA_ERROR(res, FFA_BUSY);
	} else {
		res = sp_req_echo_busy_cmd_send(own_id, own_id + 1);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	}

	return sp_success(own_id, test_source, 0);
}

/**
 * VM asking an SP to send an indirect message to another endpoint.
 * Message is sent via FFA_MSG_SEND2 ABI, and the receiver is notified through
 * a direct message.
 * The message is expected to be echoed back by an indirect message.
 */
struct ffa_value sp_indirect_msg_cmd(ffa_vm_id_t test_source,
				     ffa_vm_id_t receiver_id, uint32_t payload)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_msg *message;
	const uint32_t *echo_payload;
	struct ffa_value ret;

	ret = send_indirect_message(own_id, receiver_id, mb.send, &payload,
				    sizeof(payload),
				    FFA_NOTIFICATIONS_FLAG_DELAY_SRI);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/*
	 * Notify the receiver that got an indirect message using a direct
	 * message.
	 */
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

	return sp_success(own_id, test_source, 0);
}

static void check_rx_buffer_full_notification(void)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;
	ffa_notifications_bitmap_t framework_notifications;

	ret = ffa_notification_get(own_id, 0,
				   FFA_NOTIFICATION_FLAG_BITMAP_HYP |
					   FFA_NOTIFICATION_FLAG_BITMAP_SPM);
	framework_notifications = ffa_notification_get_from_framework(ret);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	ASSERT_TRUE(
		is_ffa_hyp_buffer_full_notification(framework_notifications) ||
		is_ffa_spm_buffer_full_notification(framework_notifications));
}

static void irq(void)
{
	ASSERT_EQ(hf_interrupt_get(), HF_NOTIFICATION_PENDING_INTID);
	check_rx_buffer_full_notification();
}

/**
 * Echo the indirect message back to sender.
 */
struct ffa_value sp_echo_indirect_msg_cmd(ffa_vm_id_t test_source)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	ffa_vm_id_t target_vm_id;
	ffa_vm_id_t source_vm_id;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_msg *message;
	const uint32_t *payload;

	if (sel1_secure_service) {
		/* S-EL1 partition, register interrupt handler for NPI. */
		exception_setup(irq, NULL);
		hf_interrupt_enable(HF_NOTIFICATION_PENDING_INTID, true,
				    INTERRUPT_TYPE_IRQ);
		arch_irq_enable();
	} else {
		/*
		 * S-EL0 partition, can't get interrupts, check notification
		 * is set.
		 */
		check_rx_buffer_full_notification();
		(void)irq;
	}

	message = (struct ffa_partition_msg *)mb.recv;
	source_vm_id = ffa_rxtx_header_sender(&message->header);
	target_vm_id = ffa_rxtx_header_receiver(&message->header);
	EXPECT_EQ(own_id, target_vm_id);

	payload = (const uint32_t *)message->payload;

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Echo message back. */
	send_indirect_message(target_vm_id, source_vm_id, mb.send, payload,
			      sizeof(*payload),
			      FFA_NOTIFICATIONS_FLAG_DELAY_SRI);

	return sp_success(own_id, test_source, 0);
}
