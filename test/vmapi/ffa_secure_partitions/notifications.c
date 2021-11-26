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

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

struct notif_cpu_entry_args {
	struct spinlock *lock;
	ffa_vcpu_index_t vcpu_id;
};

static void notif_signal_vm_to_sp(ffa_vm_id_t sender, ffa_vm_id_t receiver,
				  ffa_notifications_bitmap_t bitmap,
				  uint32_t flags)
{
	struct ffa_value res;
	ffa_vcpu_index_t vcpu_id = (flags >> 16U) & 0xFFFFU;

	/* Request receiver to bind notifications. */
	res = sp_notif_bind_cmd_send(sender, receiver, sender,
				     flags & FFA_NOTIFICATION_FLAG_PER_VCPU,
				     bitmap);
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
	EXPECT_EQ(sp_notif_get_from_sp(res), 0);
	EXPECT_EQ(sp_notif_get_from_vm(res), bitmap);

	/* Request to unbind notifications */
	res = sp_notif_unbind_cmd_send(sender, receiver, sender, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

/**
 * Test to validate notifications signaling from an SP to a VM.
 */
TEST(ffa_notifications, signaling_from_sp_to_vm)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	const ffa_vm_id_t notification_sender = SP_ID(1);
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
	notif_signal_vm_to_sp(hf_vm_get_id(), SP_ID(1),
			      FFA_NOTIFICATION_MASK(35),
			      FFA_NOTIFICATIONS_FLAG_DELAY_SRI);
}

static void cpu_entry_vm_to_sp_signaling(uintptr_t arg)
{
	struct notif_cpu_entry_args *test_args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct notif_cpu_entry_args *)arg;

	notif_signal_vm_to_sp(
		hf_vm_get_id(), SP_ID(1),
		FFA_NOTIFICATION_MASK(test_args->vcpu_id),
		FFA_NOTIFICATIONS_FLAG_DELAY_SRI |
			FFA_NOTIFICATIONS_FLAG_PER_VCPU |
			FFA_NOTIFICATIONS_FLAGS_VCPU_ID(test_args->vcpu_id));

	sl_unlock(test_args->lock);

	arch_cpu_stop();
}

TEST(ffa_notifications, per_vcpu_vm_to_sp)
{
	struct spinlock lock = SPINLOCK_INIT;
	alignas(4096) static uint8_t other_stack[MAX_CPUS - 1][4096];
	struct notif_cpu_entry_args args = {.lock = &lock};

	/* Start secondary while holding lock. */
	sl_lock(&lock);

	for (size_t i = 1; i < MAX_CPUS - 1; i++) {
		size_t hftest_cpu_index = MAX_CPUS - i;
		HFTEST_LOG(
			"Notifications signaling VM to SP. Booting CPU %u. \n",
			i);

		args.vcpu_id = i;

		EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(hftest_cpu_index),
					   other_stack[i - 1],
					   sizeof(other_stack[0]),
					   cpu_entry_vm_to_sp_signaling,
					   (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&lock);

		HFTEST_LOG("Done with CPU %u\n", i);
	}
}
