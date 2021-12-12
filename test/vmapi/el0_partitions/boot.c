/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/exception_handler.h"
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
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "boot_memory", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Accessing memory outside the given range traps the VM and yields.
 */
TEST(boot, beyond_memory_size)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "boot_memory_overrun", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_FFA_ERROR(run_res, FFA_ABORTED);
}

/**
 * Accessing memory before the start of the image traps the VM and yields.
 */
TEST(boot, memory_before_image)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "boot_memory_underrun", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_FFA_ERROR(run_res, FFA_ABORTED);
}

TEST(mem_permission, ffa_mem_get_test)
{
	struct ffa_value res;
	struct mailbox_buffers mb = set_up_mailbox();
	SERVICE_SELECT(SERVICE_VM1, "ffa_mem_perm_get", mb.send);

	/* Let the secondary get started and wait for a message. */
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	/*
	 * Send direct message to tell service VM to do FFA_MEM_PERM_GET tests.
	 */
	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	/* Check that VM's cannot use this ABI */
	res = ffa_mem_perm_get(0xDEADBEEF);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_DENIED);
}

TEST(mem_permission, ffa_mem_set_test)
{
	struct ffa_value res;
	struct mailbox_buffers mb = set_up_mailbox();
	SERVICE_SELECT(SERVICE_VM1, "ffa_mem_perm_set", mb.send);

	/* Let the secondary get started and wait for a message. */
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	/* Check that VM's cannot use this ABI */
	res = ffa_mem_perm_set(0xDEADBEEF, 0x1000, 0xf);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_DENIED);
}
