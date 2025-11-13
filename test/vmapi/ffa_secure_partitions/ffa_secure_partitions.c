/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "ffa_secure_partitions.h"

#include "hf/ffa.h"

#include "partition_services.h"

SERVICE_PARTITION_INFO_GET(service1, SERVICE1)
SERVICE_PARTITION_INFO_GET(service2, SERVICE2)
SERVICE_PARTITION_INFO_GET(service3, SERVICE3)

/**
 * Helper to setup mailbox for precondition functions.
 */
static struct mailbox_buffers get_precondition_mailbox(void)
{
	static struct mailbox_buffers mb = {.recv = NULL, .send = NULL};

	if (mb.send == NULL && mb.recv == NULL) {
		mb = set_up_mailbox();
	}

	return mb;
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an UP SP.
 */
bool service2_is_up_sp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return (service2_info->vcpu_count == 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an MP SP.
 */
bool service2_is_mp_sp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return (service2_info->vcpu_count > 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an S-EL0 SP.
 */
bool service2_is_el0(void)
{
	return (SP2_EL == 0);
}

/*
 * Send echo command and verify direct response and payload.
 */
void check_echo_payload(ffa_id_t sender_id, ffa_id_t receiver_id,
			const uint32_t msg[4])
{
	struct ffa_value res = sp_echo_cmd_send(sender_id, receiver_id, msg[0],
						msg[1], msg[2], msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
}

/*
 * Send echo command with default payload and verify response.
 */
void check_echo(ffa_id_t sender_id, ffa_id_t receiver_id)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};

	check_echo_payload(sender_id, receiver_id, msg);
}
