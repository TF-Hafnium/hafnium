/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(unmapped)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Accessing unmapped memory traps the VM.
 */
TEST(unmapped, data_unmapped)
{
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "data_unmapped", mb.send);

	EXPECT_EQ(ffa_run(SERVICE_VM1, 0).func, FFA_YIELD_32);
	EXPECT_EQ(exception_handler_receive_exception_count(mb.recv), 1);
}

/**
 * Accessing partially unmapped memory traps the VM.
 */
TEST(unmapped, straddling_data_unmapped)
{
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "straddling_data_unmapped", mb.send);

	EXPECT_EQ(ffa_run(SERVICE_VM1, 0).func, FFA_YIELD_32);
	EXPECT_EQ(exception_handler_receive_exception_count(mb.recv), 1);
}

/**
 * Executing unmapped memory traps the VM.
 */
TEST(unmapped, instruction_unmapped)
{
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "instruction_unmapped", mb.send);

	EXPECT_EQ(ffa_run(SERVICE_VM1, 0).func, FFA_YIELD_32);
	EXPECT_EQ(exception_handler_receive_exception_count(mb.recv), 1);
}
