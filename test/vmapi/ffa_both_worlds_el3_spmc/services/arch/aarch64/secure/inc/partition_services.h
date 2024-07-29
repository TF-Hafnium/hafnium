/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/* Note: this is a duplicate of
 * test/vmapi/ffa_both_worlds_el3_spmc/services/arch/aarch64/secure/inc/partition_services.h,
 * to test the EL3 SPMC
 */

#pragma once

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "test/vmapi/ffa.h"

/* Return values for the test commands. */
#define SP_SUCCESS 0
#define SP_ERROR (-1)

static inline struct ffa_value sp_success(ffa_id_t sender, ffa_id_t receiver,
					  uint64_t val)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_SUCCESS, val, 0, 0,
					0);
}

static inline struct ffa_value sp_error(ffa_id_t sender, ffa_id_t receiver,
					enum ffa_error error_code)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_ERROR, error_code,
					0, 0, 0);
}

static inline struct ffa_value sp_send_response(ffa_id_t sender,
						ffa_id_t receiver,
						uint64_t resp)
{
	return ffa_msg_send_direct_resp(sender, receiver, resp, 0, 0, 0, 0);
}

static inline int sp_resp(struct ffa_value res)
{
	return (int)res.arg3;
}

static inline int sp_get_cmd(struct ffa_value res)
{
	return (int)res.arg3;
}

static inline int sp_resp_value(struct ffa_value res)
{
	return (int)res.arg4;
}

/**
 * Command to request SP to echo payload back to the sender.
 */
#define SP_ECHO_CMD 0x6563686f

static inline struct ffa_value sp_echo_cmd_send(ffa_id_t sender,
						ffa_id_t receiver,
						uint32_t val1, uint32_t val2,
						uint32_t val3, uint32_t val4)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_ECHO_CMD, val1,
				       val2, val3, val4);
}

struct ffa_value sp_echo_cmd(ffa_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5);

/**
 * Command to request SP to run echo test with second SP.
 */
#define SP_REQ_ECHO_CMD 0x65636870

static inline struct ffa_value sp_req_echo_cmd_send(
	ffa_id_t sender, ffa_id_t receiver, uint32_t val1, uint32_t val2,
	uint32_t val3, uint32_t val4)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_REQ_ECHO_CMD, val1,
				       val2, val3, val4);
}

struct ffa_value sp_req_echo_cmd(ffa_id_t test_source, uint32_t val1,
				 uint32_t val2, uint32_t val3, uint32_t val4);

/**
 * Command to request SP to run echo denied test with second SP.
 */
#define SP_REQ_ECHO_DENIED_CMD 0x65636871

static inline struct ffa_value sp_req_echo_denied_cmd_send(ffa_id_t sender,
							   ffa_id_t receiver)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_REQ_ECHO_DENIED_CMD,
				       0, 0, 0, 0);
}

struct ffa_value sp_req_echo_denied_cmd(ffa_id_t test_source);

/**
 * Command to request an SP to perform checks using ffa_partition_info_get_regs
 * ABI.
 */
#define SP_CHECK_PARTITION_INFO_GET_REGS_CMD 0x5054567DU

static inline struct ffa_value sp_check_partition_info_get_regs_cmd_send(
	ffa_id_t test_source, ffa_id_t receiver)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_CHECK_PARTITION_INFO_GET_REGS_CMD, 0,
				       0, 0, 0);
}

struct ffa_value sp_check_partition_info_get_regs_cmd(ffa_id_t test_source);

/**
 * Command to request an SP to retrieve and increment memory.
 */
#define SP_REQ_RETRIEVE_CMD 0x65636900

static inline struct ffa_value sp_req_retrieve_cmd_send(ffa_id_t sender,
							ffa_id_t receiver,
							uint32_t handle,
							uint32_t tag,
							uint32_t flags)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_REQ_RETRIEVE_CMD,
				       handle, tag, flags, 0);
}

struct ffa_value sp_req_retrieve_cmd(ffa_id_t sender, uint32_t handle,
				     uint32_t tag, uint32_t flags,
				     struct mailbox_buffers mb);
