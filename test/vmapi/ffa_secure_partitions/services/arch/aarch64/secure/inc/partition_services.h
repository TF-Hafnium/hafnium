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
					  ffa_vm_id_t receiver, uint64_t val)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_SUCCESS, val, 0, 0,
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

/**
 * Command to request SP to run echo test with second SP.
 */
#define SP_REQ_ECHO_CMD 0x65636870

static inline struct ffa_value sp_req_echo_cmd_send(
	ffa_vm_id_t sender, ffa_vm_id_t receiver, uint32_t val1, uint32_t val2,
	uint32_t val3, uint32_t val4)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_REQ_ECHO_CMD, val1,
				       val2, val3, val4);
}

struct ffa_value sp_req_echo_cmd(ffa_vm_id_t test_source, uint32_t val1,
				 uint32_t val2, uint32_t val3, uint32_t val4);

/**
 * Command to request SP to run echo denied test with second SP.
 */
#define SP_REQ_ECHO_DENIED_CMD 0x65636871

static inline struct ffa_value sp_req_echo_denied_cmd_send(ffa_vm_id_t sender,
							   ffa_vm_id_t receiver)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_REQ_ECHO_DENIED_CMD,
				       0, 0, 0, 0);
}

struct ffa_value sp_req_echo_denied_cmd(ffa_vm_id_t test_source);

/**
 * Command to request SP to set notifications.
 */
#define SP_NOTIF_SET_CMD 0x736574U

static inline struct ffa_value sp_notif_set_cmd_send(
	ffa_vm_id_t sender, ffa_vm_id_t receiver, ffa_vm_id_t notif_receiver,
	uint32_t flags, ffa_notifications_bitmap_t bitmap)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_NOTIF_SET_CMD,
				       notif_receiver, flags,
				       (uint32_t)bitmap,	  /* lo */
				       (uint32_t)(bitmap >> 32)); /* hi */
}

static inline ffa_vm_id_t sp_notif_receiver(struct ffa_value cmd)
{
	return (ffa_vm_id_t)cmd.arg4;
}

static inline uint32_t sp_notif_flags(struct ffa_value cmd)
{
	return (uint32_t)cmd.arg5;
}

static inline ffa_notifications_bitmap_t sp_notif_bitmap(struct ffa_value cmd)
{
	return ffa_notifications_bitmap(cmd.arg6, cmd.arg7);
}

struct ffa_value sp_notif_set_cmd(ffa_vm_id_t test_source,
				  ffa_vm_id_t notif_receiver, uint32_t flags,
				  ffa_notifications_bitmap_t bitmap);

/**
 * Command to request SP to get notifications.
 */
#define SP_NOTIF_GET_CMD 0x676574U

static inline struct ffa_value sp_notif_get_cmd_send(ffa_vm_id_t test_source,
						     ffa_vm_id_t receiver,
						     uint16_t vcpu_id,
						     uint32_t flags)
{
	return ffa_msg_send_direct_req(test_source, receiver, SP_NOTIF_GET_CMD,
				       vcpu_id, flags, 0, 0);
}

static inline uint16_t sp_notif_vcpu(struct ffa_value cmd)
{
	return (uint16_t)cmd.arg4;
}

struct ffa_value sp_notif_get_cmd(ffa_vm_id_t test_source, uint16_t vcpu_id,
				  uint32_t flags);

static inline struct ffa_value sp_notif_get_success(
	ffa_vm_id_t sender, ffa_vm_id_t receiver,
	ffa_notifications_bitmap_t from_sp, ffa_notifications_bitmap_t from_vm)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_SUCCESS,
					(uint32_t)from_sp,	    /*lo*/
					(uint32_t)(from_sp >> 32),  /*hi*/
					(uint32_t)from_vm,	    /*lo*/
					(uint32_t)(from_vm >> 32)); /*hi*/
}

static inline ffa_notifications_bitmap_t sp_notif_get_from_sp(
	struct ffa_value res)
{
	return ffa_notifications_bitmap(res.arg4, res.arg5);
}

static inline ffa_notifications_bitmap_t sp_notif_get_from_vm(
	struct ffa_value res)
{
	return ffa_notifications_bitmap(res.arg6, res.arg7);
}

/**
 * Command to request SP to bind notifications to the specified sender.
 */
#define SP_NOTIF_BIND_CMD 0x42494e44U

static inline struct ffa_value sp_notif_bind_cmd_send(
	ffa_vm_id_t sender, ffa_vm_id_t receiver, ffa_vm_id_t notif_sender,
	uint32_t flags, ffa_notifications_bitmap_t bitmap)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_NOTIF_BIND_CMD,
				       notif_sender, flags,
				       (uint32_t)bitmap,	  /* lo */
				       (uint32_t)(bitmap >> 32)); /* hi */
}

static inline ffa_vm_id_t sp_notif_bind_sender(struct ffa_value cmd)
{
	return (ffa_vm_id_t)cmd.arg4;
}

struct ffa_value sp_notif_bind_cmd(ffa_vm_id_t test_source,
				   ffa_vm_id_t notif_sender, uint32_t flags,
				   ffa_notifications_bitmap_t bitmap);

/**
 * Command to request SP to unbind notifications from the specified sender.
 */
#define SP_NOTIF_UNBIND_CMD SP_NOTIF_BIND_CMD + 1

static inline struct ffa_value sp_notif_unbind_cmd_send(
	ffa_vm_id_t sender, ffa_vm_id_t receiver, ffa_vm_id_t notif_sender,
	ffa_notifications_bitmap_t bitmap)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_NOTIF_UNBIND_CMD,
				       notif_sender, 0,
				       (uint32_t)bitmap,	  /* lo */
				       (uint32_t)(bitmap >> 32)); /* hi */
}

struct ffa_value sp_notif_unbind_cmd(ffa_vm_id_t test_source,
				     ffa_vm_id_t notif_sender,
				     ffa_notifications_bitmap_t bitmap);

/**
 * Command to request an SP to send an indirect message.
 */
#define SP_INDIR_MSG_CMD 0x494dU

static inline struct ffa_value sp_indirect_msg_cmd_send(
	ffa_vm_id_t sender, ffa_vm_id_t receiver, ffa_vm_id_t msg_receiver,
	uint32_t payload)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_INDIR_MSG_CMD,
				       msg_receiver, payload, 0, 0);
}

static inline ffa_vm_id_t sp_indirect_msg_receiver(struct ffa_value cmd)
{
	return (ffa_vm_id_t)cmd.arg4;
}

static inline uint32_t sp_indirect_msg_payload(struct ffa_value cmd)
{
	return cmd.arg5;
}

struct ffa_value sp_indirect_msg_cmd(ffa_vm_id_t test_source,
				     ffa_vm_id_t receiver_id, uint32_t payload);

/**
 * Command to notify an SP an indirect message is available in it's RX buffer,
 * echoes it back to sender.
 */
#define SP_ECHO_INDIR_MSG_CMD 0x43494eU

static inline struct ffa_value sp_echo_indirect_msg_cmd_send(
	ffa_vm_id_t sender, ffa_vm_id_t receiver)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_ECHO_INDIR_MSG_CMD,
				       0, 0, 0, 0);
}

struct ffa_value sp_echo_indirect_msg_cmd(ffa_vm_id_t test_source);

struct ffa_value sp_check_ffa_return_resp(ffa_vm_id_t test_source,
					  ffa_vm_id_t own_id,
					  struct ffa_value res);

/**
 * Command to request SP to validate if core index passed to the SP is as
 * expected.
 */
#define SP_CHECK_CPU_IDX_CMD 0x76637075U

static inline struct ffa_value sp_check_cpu_idx_cmd_send(
	ffa_vm_id_t test_source, ffa_vm_id_t receiver, ffa_vcpu_index_t cpu_idx)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_CHECK_CPU_IDX_CMD, cpu_idx, 0, 0, 0);
}

static inline ffa_vcpu_index_t sp_check_cpu_idx(struct ffa_value cmd)
{
	return (ffa_vcpu_index_t)cmd.arg4;
}

struct ffa_value sp_check_cpu_idx_cmd(ffa_vm_id_t test_source,
				      ffa_vcpu_index_t received_cpu_idx);

/**
 * Command to request SP to actively wait in a busy loop.
 */
#define SP_WAIT_BUSY_LOOP_CMD 0x42555359

static inline struct ffa_value sp_busy_loop_cmd_send(ffa_vm_id_t test_source,
						     ffa_vm_id_t receiver,
						     uint64_t loop_count)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_WAIT_BUSY_LOOP_CMD, loop_count, 0, 0,
				       0);
}

/**
 * Command to request an SP to perform various state transitions through FFA
 * ABIs.
 */
#define SP_CHECK_STATE_TRANSITIONS_CMD 0x5052544dU
static inline struct ffa_value sp_check_state_transitions_cmd_send(
	ffa_vm_id_t test_source, ffa_vm_id_t receiver, ffa_vm_id_t companion_sp)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_CHECK_STATE_TRANSITIONS_CMD,
				       companion_sp, 0, 0, 0);
}

struct ffa_value sp_check_state_transitions_cmd(ffa_vm_id_t test_source,
						ffa_vm_id_t companion_sp);
