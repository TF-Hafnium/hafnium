/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(boot)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * The VM gets its memory size on boot, and can access it all.
 */
TEST(boot, memory_size)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "boot_memory", mb.send);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
}

/**
 * Accessing memory outside the given range traps the VM and yields.
 */
TEST(boot, beyond_memory_size)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value run_res;

	SERVICE_SELECT(service1_info->vm_id, "boot_memory_overrun", mb.send);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

/**
 * Accessing memory before the start of the image traps the VM and yields.
 */
TEST(boot, memory_before_image)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value run_res;

	SERVICE_SELECT(service1_info->vm_id, "boot_memory_underrun", mb.send);

	run_res = ffa_run(service1_info->vm_id, 0);
	EXPECT_TRUE(exception_received(&run_res, mb.recv));
}

TEST_PRECONDITION(boot, memory_manifest, service1_is_not_vm)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value run_res;

	SERVICE_SELECT(service1_info->vm_id, "boot_memory_manifest", mb.send);
	run_res = ffa_run(service1_info->vm_id, 0);

	EXPECT_FALSE(exception_received(&run_res, mb.recv));
}
