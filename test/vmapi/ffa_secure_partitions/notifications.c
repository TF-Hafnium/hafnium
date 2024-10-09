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

static void notif_signal_vm_to_sp(ffa_id_t sender, ffa_id_t receiver,
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

static void notif_signal_sp_to_vm(ffa_id_t sender, ffa_id_t receiver,
				  ffa_notifications_bitmap_t bitmap,
				  uint32_t flags)
{
	struct ffa_value res;
	ffa_vcpu_index_t vcpu_id = (ffa_vcpu_index_t)(flags >> 16U) & 0xFFFFU;

	/* Arbitrarily bind notification. */
	res = ffa_notification_bind(sender, receiver,
				    flags & FFA_NOTIFICATIONS_FLAG_PER_VCPU,
				    bitmap);
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

	EXPECT_EQ(ffa_notification_get_from_sp(res), bitmap);
	EXPECT_EQ(res.arg4, 0);
	EXPECT_EQ(res.arg5, 0);
	EXPECT_EQ(res.arg6, 0);
	EXPECT_EQ(res.arg7, 0);

	res = ffa_notification_unbind(sender, receiver, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
}

/**
 * Test to validate notifications signaling from an SP to a VM.
 */
TEST(ffa_notifications, signaling_from_sp_to_vm)
{
	notif_signal_sp_to_vm(SP_ID(1), hf_vm_get_id(),
			      FFA_NOTIFICATION_MASK(20),
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
			      FFA_NOTIFICATION_MASK(35),
			      FFA_NOTIFICATIONS_FLAG_DELAY_SRI);
}

static void cpu_entry_vm_to_sp_signaling(uintptr_t arg)
{
	struct ffa_value res;
	struct notif_cpu_entry_args *test_args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct notif_cpu_entry_args *)arg;
	ffa_vcpu_index_t sp_vcpu_id = test_args->is_sp_up
					      ? ((ffa_vcpu_index_t)0)
					      : test_args->vcpu_id;

	/*
	 * Make receiver SP reach message loop.
	 * TODO: the FFA_RUN ABI only needs to be called for the MP UP endpoints
	 * to bootstrap the EC in the current core. Though there is an issue
	 * with the current FFA_RUN implementation: it returns back to the
	 * caller with FFA_MSG_WAIT interface, without resuming the target
	 * SP. When fixing the FFA_RUN issue, this bit of code needs addressing.
	 */
	res = ffa_run(test_args->sp_id, sp_vcpu_id);
	EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

	notif_signal_vm_to_sp(
		hf_vm_get_id(), test_args->sp_id,
		FFA_NOTIFICATION_MASK(test_args->vcpu_id),
		FFA_NOTIFICATIONS_FLAG_DELAY_SRI |
			FFA_NOTIFICATIONS_FLAG_PER_VCPU |
			FFA_NOTIFICATIONS_FLAGS_VCPU_ID(sp_vcpu_id));

	sl_unlock(test_args->lock);

	arch_cpu_stop();
}

static void cpu_entry_sp_to_vm_signaling(uintptr_t arg)
{
	struct ffa_value res;
	struct notif_cpu_entry_args *test_args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct notif_cpu_entry_args *)arg;
	ffa_vcpu_index_t sp_vcpu_id = test_args->is_sp_up
					      ? ((ffa_vcpu_index_t)0)
					      : test_args->vcpu_id;

	/*
	 * Make sender SP reach message loop.
	 * TODO: the FFA_RUN ABI only needs to be called for the MP UP endpoints
	 * to bootstrap the EC in the current core. Though there is an issue
	 * with the current FFA_RUN implementation: it returns back to the
	 * caller with FFA_MSG_WAIT interface, without resuming the target
	 * SP. When fixing the FFA_RUN issue, this bit of code needs addressing.
	 */
	res = ffa_run(test_args->sp_id, sp_vcpu_id);
	EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

	notif_signal_sp_to_vm(
		test_args->sp_id, hf_vm_get_id(),
		FFA_NOTIFICATION_MASK(test_args->vcpu_id),
		FFA_NOTIFICATIONS_FLAG_DELAY_SRI |
			FFA_NOTIFICATIONS_FLAG_PER_VCPU |
			FFA_NOTIFICATIONS_FLAGS_VCPU_ID(test_args->vcpu_id));

	sl_unlock(test_args->lock);

	arch_cpu_stop();
}

static void base_per_cpu_notifications_test(void (*cpu_entry)(uintptr_t arg))
{
	struct spinlock lock = SPINLOCK_INIT;
	struct notif_cpu_entry_args args = {.lock = &lock};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	args.sp_id = service2_info->vm_id;
	args.is_sp_up = service2_info->vcpu_count == 1U;

	/* Start secondary while holding lock. */
	sl_lock(&lock);

	for (size_t i = 1; i < MAX_CPUS - 1; i++) {
		HFTEST_LOG("Notifications signaling VM to SP. Booting CPU %zu.",
			   i);

		args.vcpu_id = i;

		EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(i),
					   hftest_get_secondary_ec_stack(i),
					   cpu_entry, (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&lock);

		HFTEST_LOG("Done with CPU %zu\n", i);
	}
}

TEST_PRECONDITION(ffa_notifications, per_vcpu_vm_to_sp, service2_is_mp_sp)
{
	base_per_cpu_notifications_test(cpu_entry_vm_to_sp_signaling);
}

TEST(ffa_notifications, per_vcpu_sp_to_vm)
{
	base_per_cpu_notifications_test(cpu_entry_sp_to_vm_signaling);
}

TEST(ffa_notifications, fail_if_mbz_set_in_notification_get)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind notification. */
	res = ffa_notification_bind(sender, own_id, 0,
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id, 0,
				    FFA_NOTIFICATION_MASK(1));
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
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id,
				    ~(FFA_NOTIFICATION_FLAG_PER_VCPU |
				      FFA_NOTIFICATIONS_FLAG_DELAY_SRI),
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ((int32_t)sp_resp_value(res), FFA_INVALID_PARAMETERS);
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
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id,
				    FFA_NOTIFICATIONS_FLAGS_VCPU_ID(5),
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ((int32_t)sp_resp_value(res), FFA_INVALID_PARAMETERS);
}

TEST(ffa_notifications, fail_if_global_notif_set_as_per_vcpu)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind global notification. */
	res = ffa_notification_bind(sender, own_id, 0,
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification: as per-vCPU. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id,
				    FFA_NOTIFICATION_FLAG_PER_VCPU,
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ((int32_t)sp_resp_value(res), FFA_INVALID_PARAMETERS);
}

TEST(ffa_notifications, fail_if_per_vcpu_notif_set_as_global)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	/* Arbitrarily bind per-vCPU notification. */
	res = ffa_notification_bind(sender, own_id,
				    FFA_NOTIFICATION_FLAG_PER_VCPU,
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Requesting sender to set notification: as global. */
	res = sp_notif_set_cmd_send(own_id, sender, own_id, 0,
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_ERROR);
	EXPECT_EQ((int32_t)sp_resp_value(res), FFA_INVALID_PARAMETERS);
}

TEST(ffa_notifications, fail_if_mbz_set_in_notifications_bind)
{
	struct ffa_value res;
	const ffa_id_t sender = SP_ID(1);
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_notification_bind(sender, own_id,
				    ~FFA_NOTIFICATION_FLAG_PER_VCPU,
				    FFA_NOTIFICATION_MASK(1));
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}
