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
#include "test/vmapi/ffa.h"

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
