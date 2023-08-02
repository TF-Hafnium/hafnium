/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * Communicates with partition via direct messaging to validate functioning of
 * direct request/response interfaces.
 */
TEST(ffa_msg_send_direct_req, succeeds_nwd_to_sp_echo)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
			       msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
}

/**
 * Validate SP to SP direct messaging is functioning as expected.
 */
TEST(ffa_msg_send_direct_req, succeeds_sp_to_sp_echo)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_req_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
				   msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

/**
 * Test that if a direct message request is sent to an SP that is already
 * waiting for a direct message response an DENIED error code is returned.
 */
TEST(ffa_msg_send_direct_req, fails_direct_req_to_waiting_sp)
{
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_req_echo_denied_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}
