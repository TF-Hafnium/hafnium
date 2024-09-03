/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Test to confirm that a Pointer Authentication fault in an EL0 partition will
 * result in the partition being aborted.
 */
TEST_PRECONDITION(pauth, pauth_fault_el0, service2_is_el0)
{
	const ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;
	sp_pauth_fault_cmd_send(own_id, SP_ID(2));

	res = ffa_run(SP_ID(2), 0);
	EXPECT_FFA_ERROR(res, FFA_ABORTED);
}
