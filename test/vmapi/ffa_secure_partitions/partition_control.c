/*
 * Copyright 2021 The Hafnium Authors.
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

TEAR_DOWN(ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Communicates with partition via direct messaging to validate functioning of
 * Direct Message interfaces.
 */
TEST(ffa_msg_send_direct_req, succeeds_nwd_to_sp_echo)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	const ffa_vm_id_t receiver_id = HF_OTHER_WORLD_ID + 1;
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
			       msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
}

/**
 * Test to validate notifications signaling from an SP to a VM.
 */
TEST(ffa_notifications, signaling_from_sp_to_vm)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	const ffa_vm_id_t notification_sender = HF_OTHER_WORLD_ID + 1;
	const ffa_notifications_bitmap_t bitmap = FFA_NOTIFICATION_MASK(20);

	/* Arbitrarily bind notification 20 */
	res = ffa_notification_bind(notification_sender, own_id, 0, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, notification_sender, own_id,
				    FFA_NOTIFICATIONS_FLAG_DELAY_SRI, bitmap);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Retrieve FF-A endpoints with pending notifications. */
	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/* Retrieving pending notification */
	res = ffa_notification_get(own_id, 0, FFA_NOTIFICATION_FLAG_BITMAP_SP);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	EXPECT_EQ(ffa_notification_get_from_sp(res), bitmap);
	EXPECT_EQ(res.arg4, 0);
	EXPECT_EQ(res.arg5, 0);
	EXPECT_EQ(res.arg6, 0);
	EXPECT_EQ(res.arg7, 0);

	res = ffa_notification_unbind(notification_sender, own_id, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
}

/**
 * Validate notifications signaling from VM to an SP.
 */
TEST(ffa_notifications, signaling_from_vm_to_sp)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	const ffa_vm_id_t notification_receiver = HF_OTHER_WORLD_ID + 1;
	const ffa_notifications_bitmap_t bitmap = FFA_NOTIFICATION_MASK(35);

	/* Request receiver to bind notifications. */
	res = sp_notif_bind_cmd_send(own_id, notification_receiver, own_id, 0,
				     bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = ffa_notification_set(own_id, notification_receiver,
				   FFA_NOTIFICATIONS_FLAG_DELAY_SRI, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/* Request to get notifications pending */
	res = sp_notif_get_cmd_send(own_id, notification_receiver, 0,
				    FFA_NOTIFICATION_FLAG_BITMAP_VM);

	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	EXPECT_EQ(sp_notif_get_from_sp(res), 0);
	EXPECT_EQ(sp_notif_get_from_vm(res), bitmap);

	/* Request to unbind notifications */
	res = sp_notif_unbind_cmd_send(own_id, notification_receiver, own_id,
				       bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

TEST(ffa, ffa_partition_info_get_uuid_null)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid uuid;

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/*
	 * A Null UUID requests information for all partitions
	 * including VMs and SPs.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Check that expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect two partitions. */
	EXPECT_EQ(ret.arg2, 2);

	/* Expect the PVM as first partition. */
	EXPECT_EQ(partitions[0].vm_id, hf_vm_get_id());
	EXPECT_EQ(partitions[0].vcpu_count, 8);

	/* Expect a SP as second partition. */
	EXPECT_EQ(partitions[1].vm_id, HF_SPMC_VM_ID + 1);
	EXPECT_EQ(partitions[1].vcpu_count, 8);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(ffa, ffa_partition_info_get_uuid_fixed)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid uuid;

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/* Search for a known secure partition UUID. */
	ffa_uuid_init(0xa609f132, 0x6b4f, 0x4c14, 0x9489, &uuid);

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect one partition. */
	EXPECT_EQ(ret.arg2, 1);

	/* Expect a secure partition. */
	EXPECT_EQ(partitions[0].vm_id, HF_SPMC_VM_ID + 1);
	EXPECT_EQ(partitions[0].vcpu_count, 8);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(ffa, ffa_partition_info_get_uuid_unknown)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	/* Search for a unknown partition UUID. */
	ffa_uuid_init(1, 1, 1, 1, &uuid);

	/* Expect no partition is found with such UUID. */
	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
}
