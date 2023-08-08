/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "partition_services.h"

#include "hf/arch/irq.h"
#include "hf/arch/types.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

struct ffa_value sp_echo_cmd(ffa_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5)
{
	ffa_id_t own_id = hf_vm_get_id();
	return ffa_msg_send_direct_resp(own_id, receiver, val1, val2, val3,
					val4, val5);
}

struct ffa_value sp_req_echo_cmd(ffa_id_t test_source, uint32_t val1,
				 uint32_t val2, uint32_t val3, uint32_t val4)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, own_id + 1, val1, val2, val3, val4);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, val1);
	EXPECT_EQ(res.arg5, val2);
	EXPECT_EQ(res.arg6, val3);
	EXPECT_EQ(res.arg7, val4);

	return sp_success(own_id, test_source, 0);
}

struct ffa_value sp_req_echo_denied_cmd(ffa_id_t test_source)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	if (!ffa_is_vm_id(test_source)) {
		res = ffa_msg_send_direct_req(own_id, test_source, 0, 0, 0, 0,
					      0);
		EXPECT_FFA_ERROR(res, FFA_DENIED);
	} else {
		res = sp_req_echo_denied_cmd_send(own_id, own_id + 1);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	}

	return sp_success(own_id, test_source, 0);
}

/**
 * This test illustrates the checks performed by the RTM_FFA_DIR_REQ partition
 * runtime model for various transitions requested by SP through invocation of
 * FFA ABIs.
 */
struct ffa_value sp_check_state_transitions_cmd(ffa_id_t test_source,
						ffa_id_t companion_sp_id)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	/*
	 * The invocation of FFA_MSG_SEND_DIRECT_REQ under RTM_FFA_DIR_REQ is
	 * already part of the `succeeds_sp_to_sp_echo` test belonging to the
	 * `ffa_msg_send_direct_req` testsuite.
	 */

	/*
	 * Test invocation of FFA_MSG_SEND_DIRECT_RESP to an endpoint other
	 * than the one that allocated CPU cycles.
	 */
	res = ffa_msg_send_direct_resp(own_id, companion_sp_id, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	/* Test invocation of FFA_MSG_WAIT. */
	res = ffa_msg_wait();
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	/* Test invocation of FFA_YIELD. */
	res = ffa_yield();
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	/* TODO: test the invocation of FFA_RUN ABI.*/
	/* Perform legal invocation of FFA_MSG_SEND_DIRECT_RESP. */
	return sp_success(own_id, test_source, 0);
}
