/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

/* Return values for the test commands. */
#define SP_SUCCESS 0
#define SP_ERROR -1

static inline struct ffa_value sp_success(ffa_vm_id_t sender,
					  ffa_vm_id_t receiver)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_SUCCESS, 0, 0, 0,
					0);
}

static inline struct ffa_value sp_error(ffa_vm_id_t sender,
					ffa_vm_id_t receiver,
					uint32_t error_code)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_ERROR, error_code,
					0, 0, 0);
}

static inline int sp_resp(struct ffa_value res)
{
	return (int)res.arg3;
}

/**
 * Command to request SP to echo payload back to the sender.
 */
#define SP_ECHO_CMD 0x6563686f

static inline struct ffa_value sp_echo_cmd_send(ffa_vm_id_t sender,
						ffa_vm_id_t receiver,
						uint32_t val1, uint32_t val2,
						uint32_t val3, uint32_t val4)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_ECHO_CMD, val1,
				       val2, val3, val4);
}

struct ffa_value sp_echo_cmd(ffa_vm_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5);
