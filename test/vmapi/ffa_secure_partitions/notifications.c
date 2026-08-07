/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/spinlock.h"

#include "vmapi/hf/call.h"

#include "ffa_endpoints.h"
#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

struct notif_cpu_entry_args {
	struct spinlock *lock;
	ffa_vcpu_index_t vcpu_id;
	ffa_id_t sp_id;
	bool is_sp_up;
};

/*
 * Use notification IDs from the first, second and final 64-bit words to
 * verify that the complete 384-bit bitmap is transported end to end.
 */
static ffa_notifications_bitmap_t notification2_test_bitmap(void)
{
	ffa_notifications_bitmap_t bitmap;

	ffa_notification_bitmap_init(&bitmap);
	ffa_notification_bitmap_set(&bitmap, 20);
	ffa_notification_bitmap_set(&bitmap, 64);
	ffa_notification_bitmap_set(&bitmap, 383);

	return bitmap;
}

SET_UP(ffa_notifications2)
{
	ASSERT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);
}

static void notif_signal_vm_to_sp(ffa_id_t sender, ffa_id_t receiver,
				  ffa_notifications_bitmap_t bitmap,
				  uint32_t flags)
{
	struct ffa_value res;
	ffa_vcpu_index_t vcpu_id = (flags >> 16U) & 0xFFFFU;

	/* Request receiver to bind notifications. */
	res = sp_notif_bind_cmd_send(sender, receiver, sender, 0, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = ffa_notification_set(sender, receiver, flags, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/* Request to get notifications pending */
	res = sp_notif_get_cmd_send(sender, receiver, vcpu_id,
				    FFA_NOTIFICATION_FLAG_BITMAP_VM);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	EXPECT_TRUE(ffa_notification_bitmap_is_zero(sp_notif_get_from_sp(res)));
	EXPECT_EQ(ffa_notification_bitmap_low64(sp_notif_get_from_vm(res)),
		  ffa_notification_bitmap_low64(bitmap));

	/* Request to unbind notifications */
	res = sp_notif_unbind_cmd_send(sender, receiver, sender, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void notif_signal_sp_to_vm(ffa_id_t sender, ffa_id_t receiver,
				  ffa_notifications_bitmap_t bitmap,
				  uint32_t flags)
{
	struct ffa_value res;
	ffa_vcpu_index_t vcpu_id = (ffa_vcpu_index_t)(flags >> 16U) & 0xFFFFU;

	/* Arbitrarily bind notification. */
	res = ffa_notification_bind(sender, receiver, 0, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(receiver, sender, receiver, flags, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Retrieve FF-A endpoints with pending notifications. */
	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/* Retrieving pending notification. */
	res = ffa_notification_get(receiver, vcpu_id,
				   FFA_NOTIFICATION_FLAG_BITMAP_SP);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	EXPECT_EQ(ffa_notification_bitmap_low64(
			  ffa_notification_get_from_sp(res)),
		  ffa_notification_bitmap_low64(bitmap));
	EXPECT_EQ(res.arg4, 0);
	EXPECT_EQ(res.arg5, 0);
	EXPECT_EQ(res.arg6, 0);
	EXPECT_EQ(res.arg7, 0);

	res = ffa_notification_unbind(sender, receiver, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
}

static void notif2_signal_sp_to_vm(ffa_id_t sender, ffa_id_t receiver,
				   const struct ffa_uuid *sender_uuid,
				   ffa_notifications_bitmap_t bitmap,
				   uint64_t flags)
{
	struct ffa_value res;
	ffa_notifications_bitmap_t empty;
	ffa_vcpu_index_t vcpu_id = (ffa_vcpu_index_t)(flags >> 16U) & 0xFFFFU;

	ffa_notification_bitmap_init(&empty);

	/* Bind notifications from the sender SP to the receiver VM. */
	res = ffa_notification_bind2(sender, receiver, 0U, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Request the sender SP to set notifications. */
	res = sp_notif_set2_cmd_send(receiver, sender, sender_uuid, receiver,
				     flags, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);

	/* Retrieve FF-A endpoints with pending notifications. */
	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/* Retrieve the notifications sent by the SP. */
	res = ffa_notification_get2(receiver, vcpu_id,
				    FFA_NOTIFICATION_FLAG_BITMAP_SP, empty,
				    empty, 0U, 0U);
	EXPECT_EQ(res.func, FFA_SUCCESS_64);
	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_from_get2_sp(res), bitmap));
	EXPECT_TRUE(ffa_notification_bitmap_is_zero(
		ffa_notification_bitmap_from_get2_vm(res)));

	res = ffa_notification_unbind2(sender, receiver, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
}

static void notif2_signal_vm_to_sp(ffa_id_t sender, ffa_id_t receiver,
				   const struct ffa_uuid *receiver_uuid,
				   ffa_notifications_bitmap_t bitmap,
				   uint64_t flags,
				   ffa_notifications_bitmap_t mask)
{
	struct ffa_value res;
	ffa_vcpu_index_t vcpu_id = (flags >> 16U) & 0xFFFFU;
	ffa_notifications_bitmap_t empty;
	ffa_notifications_bitmap_t expected;
	ffa_notifications_bitmap_t remaining;

	ffa_notification_bitmap_init(&empty);

	/* Notifications returned by the first masked GET2. */
	expected = ffa_notification_bitmap_exclude(bitmap, mask);

	/* Masked notifications retained for the second GET2. */
	remaining = ffa_notification_bitmap_and(bitmap, mask);

	/* Request the receiver SP to bind notifications. */
	res = sp_notif_bind2_cmd_send(sender, receiver, receiver_uuid, sender,
				      0U, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);

	res = ffa_notification_set2(sender, receiver, flags, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/*
	 * Masked notifications must remain pending while all other selected
	 * notifications are retrieved.
	 */
	res = sp_notif_get2_cmd_send(sender, receiver, receiver_uuid, vcpu_id,
				     FFA_NOTIFICATION_FLAG_BITMAP_VM, mask);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);
	EXPECT_TRUE(ffa_notification_bitmap_equal(sp_notif_get2_bitmap(res),
						  expected));

	/* Retrieve the notifications which were masked by the first GET2. */
	res = sp_notif_get2_cmd_send(sender, receiver, receiver_uuid, vcpu_id,
				     FFA_NOTIFICATION_FLAG_BITMAP_VM, empty);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);
	EXPECT_TRUE(ffa_notification_bitmap_equal(sp_notif_get2_bitmap(res),
						  remaining));

	/* Request the receiver SP to unbind notifications. */
	res = sp_notif_unbind2_cmd_send(sender, receiver, receiver_uuid, sender,
					bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);
}

static void notif2_signal_sp_to_sp(ffa_id_t sender, ffa_id_t receiver,
				   const struct ffa_uuid *sender_uuid,
				   const struct ffa_uuid *receiver_uuid,
				   ffa_notifications_bitmap_t bitmap,
				   uint64_t flags)
{
	ffa_id_t test_source = hf_vm_get_id();
	ffa_vcpu_index_t vcpu_id = (ffa_vcpu_index_t)(flags >> 16U) & 0xFFFFU;
	ffa_notifications_bitmap_t empty;
	struct ffa_value res;

	ffa_notification_bitmap_init(&empty);

	/* Request the receiver SP to bind notifications from the sender SP. */
	res = sp_notif_bind2_cmd_send(test_source, receiver, receiver_uuid,
				      sender, 0U, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);

	/* Request the sender SP to set notifications for the receiver SP. */
	res = sp_notif_set2_cmd_send(test_source, sender, sender_uuid, receiver,
				     flags, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);

	/* Retrieve FF-A endpoints with pending notifications. */
	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);

	/* Request the receiver SP to retrieve notifications from an SP. */
	res = sp_notif_get2_cmd_send(test_source, receiver, receiver_uuid,
				     vcpu_id, FFA_NOTIFICATION_FLAG_BITMAP_SP,
				     empty);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);
	EXPECT_TRUE(ffa_notification_bitmap_equal(sp_notif_get2_bitmap(res),
						  bitmap));

	/* Request the receiver SP to unbind notifications from the sender SP */
	res = sp_notif_unbind2_cmd_send(test_source, receiver, receiver_uuid,
					sender, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp2(res), SP_SUCCESS);
}

/**
 * Test to validate notifications signaling from an SP to a VM.
 */
TEST(ffa_notifications, signaling_from_sp_to_vm)
{
	notif_signal_sp_to_vm(SP_ID(1), hf_vm_get_id(),
			      ffa_notification_bitmap_single(20),
			      FFA_NOTIFICATIONS_FLAG_DELAY_SRI);
}

/**
 * Validate notifications signaling from VM to an SP.
 */
TEST(ffa_notifications, signaling_from_vm_to_sp)
{
	/*
	 * This test can't communicate with SP_ID(1).
	 * Target SP should be FF-A v1.1 or newer.
	 */
	notif_signal_vm_to_sp(hf_vm_get_id(), SP_ID(2),
			      ffa_notification_bitmap_single(35),
			      FFA_NOTIFICATIONS_FLAG_DELAY_SRI);
}

TEST(ffa_notifications, fail_if_mbz_set_in_notification_get)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind notification. */
	res = ffa_notification_bind(sender, own_id, 0,
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id, 0,
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Check return is FFA_INVALID_PARAMETERS if any bit that MBZ is set. */
	res = ffa_notification_get(own_id, 0, 0xFF00U);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

TEST(ffa_notifications, fail_if_mbz_set_in_notification_set)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind notification. */
	res = ffa_notification_bind(sender, own_id, 0,
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id,
				    ~(FFA_NOTIFICATION_FLAG_PER_VCPU |
				      FFA_NOTIFICATIONS_FLAG_DELAY_SRI),
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ(sp_resp_value(res), FFA_INVALID_PARAMETERS);
}

/**
 * Test that setting global notifications, specifying vCPU other than
 * 0 fails with the appropriate error code.
 */
TEST(ffa_notifications, fail_if_global_notif_vcpu_not_zero)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind notification. */
	res = ffa_notification_bind(sender, own_id, 0,
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id,
				    FFA_NOTIFICATIONS_FLAGS_VCPU_ID(5),
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ(sp_resp_value(res), FFA_INVALID_PARAMETERS);
}

TEST(ffa_notifications, fail_if_global_notif_set_as_per_vcpu)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind global notification. */
	res = ffa_notification_bind(sender, own_id, 0,
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification: as per-vCPU. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id,
				    FFA_NOTIFICATION_FLAG_PER_VCPU,
				    ffa_notification_bitmap_single(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ(sp_resp_value(res), FFA_INVALID_PARAMETERS);
}

TEST(ffa_notifications, fail_if_mbz_set_in_notifications_bind)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_notification_bind(sender, own_id,
				    ~FFA_NOTIFICATION_FLAG_PER_VCPU,
				    ffa_notification_bitmap_single(1));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Test to validate Notification2 signaling from an SP to a VM.
 */
TEST(ffa_notifications2, signaling_from_sp_to_vm)
{
	const struct ffa_uuid sender_uuid = SERVICE2;

	/*
	 * Receiver VM: BIND2
	 * Sender SP:   SET2 through a service command
	 * Receiver VM: GET2 returns {20, 64, 383} from the SP bitmap
	 * Receiver VM: UNBIND2
	 */
	/* Direct request2 requires both endpoints to support FF-A v1.2 or
	 * later. */
	notif2_signal_sp_to_vm(SP_ID(2), hf_vm_get_id(), &sender_uuid,
			       notification2_test_bitmap(),
			       FFA_NOTIFICATIONS_FLAG_DELAY_SRI);
}

/**
 * Test to validate Notification2 signaling from a VM to an SP.
 */
TEST(ffa_notifications2, signaling_from_vm_to_sp)
{
	const struct ffa_uuid receiver_uuid = SERVICE2;
	/*
	 * Receiver SP: BIND2
	 * Sender VM:   SET2
	 * Receiver SP: GET2 with mask {64} returns {20, 383}
	 * Receiver SP: GET2 with an empty mask returns {64}
	 * Receiver SP: UNBIND2
	 */
	notif2_signal_vm_to_sp(hf_vm_get_id(), SP_ID(2), &receiver_uuid,
			       notification2_test_bitmap(), 0U,
			       ffa_notification_bitmap_single(64));
}

/**
 * Test to validate Notification2 signaling from an SP to another SP.
 * The primary VM controls the test while the two SPs perform the notification
 * operations.
 */
TEST(ffa_notifications2, signaling_from_sp_to_sp)
{
	const struct ffa_uuid sender_uuid = SERVICE3;
	const struct ffa_uuid receiver_uuid = SERVICE2;

	/*
	 * Receiver SP2: BIND2 through a service command
	 * Sender SP3:   SET2 through a service command
	 * Receiver SP2: GET2 returns {20, 64, 383} from the SP bitmap
	 * Receiver SP2: UNBIND2 through a service command
	 *
	 * The primary VM controls both SPs.
	 */

	notif2_signal_sp_to_sp(SP_ID(3), SP_ID(2), &sender_uuid, &receiver_uuid,
			       notification2_test_bitmap(), 0U);
}

/**
 * Validate notification-count discovery at the Non-secure virtual FF-A
 * interface.
 *
 * The primary VM queries the hypervisor. Both count fields encode 320
 * additional notification IDs, corresponding to 384 supported IDs.
 */
TEST(ffa_features, notification_counts_at_ns_virtual_interface)
{
	/* FF-A encodes the count above the legacy base: 384 - 64 = 320. */
	const uint32_t expected_encoded_count =
		MAX_FFA_NOTIFICATIONS - FFA_NOTIFICATION_COUNT_BASE;

	/* Mask covering the VM and SP count fields, bits[19:2]. */
	const uint32_t count_fields = (FFA_NOTIFICATION_COUNT_MASK
				       << FFA_NOTIFICATION_COUNT_VM_SHIFT) |
				      (FFA_NOTIFICATION_COUNT_MASK
				       << FFA_NOTIFICATION_COUNT_SP_SHIFT);

	/* Mask covering every defined notification-feature field, bits[19:0] */
	const uint32_t supported_fields = FFA_NOTIFY_FEAT_NO_PER_VCPU_VM |
					  FFA_NOTIFY_FEAT_NO_PER_VCPU_SP |
					  count_fields;
	struct ffa_value ret;
	uint32_t features;
	uint32_t vm_count;
	uint32_t sp_count;

	ret = ffa_features(FFA_FEATURE_NOTIFICATION);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	features = (uint32_t)ret.arg2;
	EXPECT_TRUE((features & FFA_NOTIFY_FEAT_NO_PER_VCPU_VM) != 0U);
	EXPECT_TRUE((features & FFA_NOTIFY_FEAT_NO_PER_VCPU_SP) != 0U);

	vm_count = (features >> FFA_NOTIFICATION_COUNT_VM_SHIFT) &
		   FFA_NOTIFICATION_COUNT_MASK;
	sp_count = (features >> FFA_NOTIFICATION_COUNT_SP_SHIFT) &
		   FFA_NOTIFICATION_COUNT_MASK;

	EXPECT_EQ(vm_count, expected_encoded_count);
	EXPECT_EQ(sp_count, expected_encoded_count);

	/* All bits outside the defined feature fields must remain zero. */
	EXPECT_EQ(features & ~supported_fields, 0U);
}
