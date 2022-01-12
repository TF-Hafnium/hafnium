/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "partition_services.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

struct ffa_value sp_echo_cmd(ffa_vm_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	return ffa_msg_send_direct_resp(own_id, receiver, val1, val2, val3,
					val4, val5);
}

struct ffa_value sp_req_echo_cmd(ffa_vm_id_t test_source, uint32_t val1,
				 uint32_t val2, uint32_t val3, uint32_t val4)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, own_id + 1, val1, val2, val3, val4);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, val1);
	EXPECT_EQ(res.arg5, val2);
	EXPECT_EQ(res.arg6, val3);
	EXPECT_EQ(res.arg7, val4);

	return sp_success(own_id, test_source);
}

struct ffa_value sp_req_echo_busy_cmd(ffa_vm_id_t test_source)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	if (IS_SP_ID(test_source)) {
		res = ffa_msg_send_direct_req(own_id, test_source, 0, 0, 0, 0,
					      0);
		EXPECT_FFA_ERROR(res, FFA_BUSY);
	} else {
		res = sp_req_echo_busy_cmd_send(own_id, own_id + 1);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(res.arg2, SP_SUCCESS);
	}

	return sp_success(own_id, test_source);
}
