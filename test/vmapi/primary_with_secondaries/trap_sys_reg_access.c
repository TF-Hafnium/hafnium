/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Test that S-EL0 access of system register is trapped by partition
 * manager and the SP is eventually aborted.
 */
TEST_PRECONDITION(trap_sys_reg_access, el0_sp_aborts, service1_is_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value res;

	SERVICE_SELECT(service1_info->vm_id, "sys_reg_access_trapped", mb.send);
	res = ffa_run(service1_info->vm_id, 0);

	EXPECT_FFA_ERROR(res, FFA_ABORTED);
}
