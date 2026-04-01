/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/semaphore.h"
#include "test/vmapi/ffa.h"

#define FFA_VERSION_NULL make_ffa_version(0, 0)

struct ffa_version_secondary_cpu_entry_args {
	ffa_id_t receiver_id;
	ffa_vcpu_index_t vcpu_id;
	struct mailbox_buffers mb;
	struct semaphore ready;
	struct semaphore go;
	struct semaphore done;
};

/*
 * FFA_VERSION fails for an endpoint when the framework is in use.
 */
TEST(ffa_version, ffa_version_negotiate_fwk_in_use_rxtx)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_rxtx", mb.send);
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/*
 * FFA_VERSION fails for an endpoint when the framework is in use.
 */
TEST(ffa_version, ffa_version_negotiate_fwk_in_use_mem_share)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_mem_share", mb.send);
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/*
 * FFA_VERSION fails for an endpoint with an unreclaimed memory lend.
 */
TEST(ffa_version, ffa_version_negotiate_fwk_in_use_mem_lend)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_mem_lend", mb.send);
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

TEST_PRECONDITION(ffa_version, ffa_version_negotiate_fwk_in_use_mem_borrow,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_lend_normal_memory_to_sp_and_reclaim", mb.send);
	SERVICE_SELECT(service2_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_mem_borrow", mb.send);

	/* Let memory be lent from Service 1 to Service 2. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Receive memory, access it and relinquish it in service2. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);

	/* Reclaim in service1. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Check the service2 can now negotiate its FFA_VERSION. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);
}

TEST_PRECONDITION(ffa_version, ffa_version_negotiate_fwk_not_in_use_mem_donate,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_not_in_use_mem_donate",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "ffa_memory_receive", mb.send);

	/* Donate memory and check that it does not put the framework in use. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Complete the donation so the receiver owns the memory. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);
}

TEST(ffa_version, ffa_version_negotiate_fwk_in_use_notifications_bound)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_notifications_bound",
		       mb.send);
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/*
 * FFA_VERSION fails for an SP when the framework notifications are pending.
 */
TEST(ffa_version, ffa_version_negotiate_fwk_in_use_notifications_pending)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;
	const char payload[] = "ffa version notifications";

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_notifications_pending",
		       mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, payload, sizeof(payload), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

static void cpu_entry_ffa_version_blocked_call(uintptr_t arg)
{
	struct ffa_version_secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct ffa_version_secondary_cpu_entry_args *)arg;
	struct ffa_value run_res;

	ASSERT_TRUE(args != NULL);

	SERVICE_SELECT_MP(
		args->receiver_id,
		"ffa_version_negotiate_fwk_in_use_blocked_call_observer",
		args->mb.send, args->vcpu_id);

	/* Let the primary know the observer is ready to run. */
	semaphore_signal(&args->ready);

	/* Check first with vCPU 0 blocked, then with vCPU 0 waiting. */
	for (unsigned int phase = 0; phase < 2; ++phase) {
		semaphore_wait(&args->go);

		do {
			run_res = ffa_run(args->receiver_id, args->vcpu_id);
		} while (run_res.func == FFA_ERROR_32 &&
			 ffa_error_code(run_res) == FFA_BUSY);

		EXPECT_EQ(run_res.func, FFA_YIELD_32);
		semaphore_signal(&args->done);
	}
}

TEST_PRECONDITION(ffa_version,
		  ffa_version_negotiate_fwk_in_use_blocked_ffa_call,
		  service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	const ffa_vcpu_index_t vcpu_id = 1;
	struct ffa_value ret;
	struct ffa_version_secondary_cpu_entry_args args = {
		.receiver_id = service1_info->vm_id,
		.vcpu_id = vcpu_id,
		.mb = mb,
	};

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_version_negotiate_fwk_in_use_blocked_call_blocker",
		       mb.send);

	semaphore_init(&args.ready);
	semaphore_init(&args.go);
	semaphore_init(&args.done);

	ASSERT_TRUE(hftest_cpu_start(hftest_get_cpu_id(vcpu_id),
				     hftest_get_secondary_ec_stack(vcpu_id),
				     cpu_entry_ffa_version_blocked_call,
				     (uintptr_t)&args));

	/* Wait until the observer service is ready to run on vCPU 1. */
	semaphore_wait(&args.ready);

	/* Run vCPU 0 until it blocks in FFA_YIELD. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Allow vCPU 1 to check FFA_VERSION while vCPU 0 is blocked. */
	semaphore_signal(&args.go);
	semaphore_wait(&args.done);

	/*
	 * Complete vCPU 0's FFA_YIELD and enter FFA_MSG_WAIT. WAITING does
	 * not count as an outstanding invocation, unlike BLOCKED or RUNNING.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Retry negotiation on vCPU 1 now that vCPU 0 is inactive. */
	semaphore_signal(&args.go);
	semaphore_wait(&args.done);
}
