/*
 * Copyright 2023 The Hafnium Authors.
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
 * Get partition to try write to memory that was set to RO during
 * initalisation to verify this fails.
 * This requires the ffa_mem_perm_set_ro SERVICE_SET_UP to be run
 * to set the memory permissions during initialisation.
 */
TEST(memory_permissions, ffa_mem_perm_set_ro_fails_write)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "ffa_mem_perm_set_ro_fails_write",
		       mb.send);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_ERROR_32);
}
