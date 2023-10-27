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

static inline struct ffa_value sp_success(ffa_id_t sender, ffa_id_t receiver,
					  uint64_t val)
{
	return ffa_msg_send_direct_resp(sender, receiver, SP_SUCCESS, val, 0, 0,
					0);
}

static inline struct ffa_value sp_error(ffa_id_t sender, ffa_id_t receiver,
					uint32_t error_code)
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
 * Command to request SP to set notifications.
 */
#define SP_NOTIF_SET_CMD 0x736574U

static inline struct ffa_value sp_notif_set_cmd_send(
	ffa_id_t sender, ffa_id_t receiver, ffa_id_t notif_receiver,
	uint32_t flags, ffa_notifications_bitmap_t bitmap)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_NOTIF_SET_CMD,
				       notif_receiver, flags,
				       (uint32_t)bitmap,	  /* lo */
				       (uint32_t)(bitmap >> 32)); /* hi */
}

static inline ffa_id_t sp_notif_receiver(struct ffa_value cmd)
{
	return (ffa_id_t)cmd.arg4;
}

static inline uint32_t sp_notif_flags(struct ffa_value cmd)
{
	return (uint32_t)cmd.arg5;
}

static inline ffa_notifications_bitmap_t sp_notif_bitmap(struct ffa_value cmd)
{
	return ffa_notifications_bitmap(cmd.arg6, cmd.arg7);
}

struct ffa_value sp_notif_set_cmd(ffa_id_t test_source, ffa_id_t notif_receiver,
				  uint32_t flags,
				  ffa_notifications_bitmap_t bitmap);

/**
 * Command to request SP to get notifications.
 */
#define SP_NOTIF_GET_CMD 0x676574U

static inline struct ffa_value sp_notif_get_cmd_send(ffa_id_t test_source,
						     ffa_id_t receiver,
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

struct ffa_value sp_notif_get_cmd(ffa_id_t test_source, uint16_t vcpu_id,
				  uint32_t flags);

static inline struct ffa_value sp_notif_get_success(
	ffa_id_t sender, ffa_id_t receiver, ffa_notifications_bitmap_t from_sp,
	ffa_notifications_bitmap_t from_vm)
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
	ffa_id_t sender, ffa_id_t receiver, ffa_id_t notif_sender,
	uint32_t flags, ffa_notifications_bitmap_t bitmap)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_NOTIF_BIND_CMD,
				       notif_sender, flags,
				       (uint32_t)bitmap,	  /* lo */
				       (uint32_t)(bitmap >> 32)); /* hi */
}

static inline ffa_id_t sp_notif_bind_sender(struct ffa_value cmd)
{
	return (ffa_id_t)cmd.arg4;
}

struct ffa_value sp_notif_bind_cmd(ffa_id_t test_source, ffa_id_t notif_sender,
				   uint32_t flags,
				   ffa_notifications_bitmap_t bitmap);

/**
 * Command to request SP to unbind notifications from the specified sender.
 */
#define SP_NOTIF_UNBIND_CMD SP_NOTIF_BIND_CMD + 1

static inline struct ffa_value sp_notif_unbind_cmd_send(
	ffa_id_t sender, ffa_id_t receiver, ffa_id_t notif_sender,
	ffa_notifications_bitmap_t bitmap)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_NOTIF_UNBIND_CMD,
				       notif_sender, 0,
				       (uint32_t)bitmap,	  /* lo */
				       (uint32_t)(bitmap >> 32)); /* hi */
}

struct ffa_value sp_notif_unbind_cmd(ffa_id_t test_source,
				     ffa_id_t notif_sender,
				     ffa_notifications_bitmap_t bitmap);

struct ffa_value sp_check_ffa_return_resp(ffa_id_t test_source, ffa_id_t own_id,
					  struct ffa_value res);

/**
 * Command to request SP to validate if core index passed to the SP is as
 * expected.
 */
#define SP_CHECK_CPU_IDX_CMD 0x76637075U

static inline struct ffa_value sp_check_cpu_idx_cmd_send(
	ffa_id_t test_source, ffa_id_t receiver, ffa_vcpu_index_t cpu_idx)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_CHECK_CPU_IDX_CMD, cpu_idx, 0, 0, 0);
}

static inline ffa_vcpu_index_t sp_check_cpu_idx(struct ffa_value cmd)
{
	return (ffa_vcpu_index_t)cmd.arg4;
}

struct ffa_value sp_check_cpu_idx_cmd(ffa_id_t test_source,
				      ffa_vcpu_index_t received_cpu_idx);

/**
 * Command to request SP to actively wait in a busy loop.
 */
#define SP_WAIT_BUSY_LOOP_CMD 0x42555359

static inline struct ffa_value sp_busy_loop_cmd_send(ffa_id_t test_source,
						     ffa_id_t receiver,
						     uint64_t loop_count)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_WAIT_BUSY_LOOP_CMD, loop_count, 0, 0,
				       0);
}

/**
 * Command to request an SP to perform various state transitions through FF-A
 * ABIs.
 */
#define SP_CHECK_STATE_TRANSITIONS_CMD 0x5052544dU
static inline struct ffa_value sp_check_state_transitions_cmd_send(
	ffa_id_t test_source, ffa_id_t receiver, ffa_id_t companion_sp)
{
	return ffa_msg_send_direct_req(test_source, receiver,
				       SP_CHECK_STATE_TRANSITIONS_CMD,
				       companion_sp, 0, 0, 0);
}

struct ffa_value sp_check_state_transitions_cmd(ffa_id_t test_source,
						ffa_id_t companion_sp);

/**
 * Command to request SP to enable/disable a secure virtual interrupt.
 */
#define SP_VIRTUAL_INTERRUPT_CMD 0x696e7472U

static inline struct ffa_value sp_virtual_interrupt_cmd_send(
	ffa_id_t source, ffa_id_t dest, uint32_t interrupt_id, bool enable,
	uint32_t pin)
{
	return ffa_msg_send_direct_req(source, dest, SP_VIRTUAL_INTERRUPT_CMD,
				       interrupt_id, enable, pin, 0);
}

static inline uint32_t sp_interrupt_id(struct ffa_value cmd)
{
	return cmd.arg4;
}

static inline uint32_t sp_is_interrupt_enable(struct ffa_value cmd)
{
	return cmd.arg5;
}

static inline uint32_t sp_interrupt_pin_type(struct ffa_value cmd)
{
	return cmd.arg6;
}

struct ffa_value sp_virtual_interrupt_cmd(ffa_id_t source,
					  uint32_t interrupt_id, bool enable,
					  uint32_t pin);

/**
 * Request to start trusted watchdog timer.
 * The command id is the hex representaton of the string "WDOG".
 */
#define SP_TWDOG_START_CMD 0x57444f47U

static inline struct ffa_value sp_twdog_cmd_send(ffa_id_t source, ffa_id_t dest,
						 uint64_t time)
{
	return ffa_msg_send_direct_req(source, dest, SP_TWDOG_START_CMD, time,
				       0, 0, 0);
}

struct ffa_value sp_twdog_cmd(ffa_id_t source, uint64_t time);

/**
 * Request SP to map MMIO region of Trusted Watchdog peripheral into it's
 * Stage-1 address space.
 * The command id is the hex representaton of the string "MAPW".
 */
#define SP_TWDOG_MAP_CMD 0x4D415057U

static inline struct ffa_value sp_twdog_map_cmd_send(ffa_id_t source,
						     ffa_id_t dest)
{
	return ffa_msg_send_direct_req(source, dest, SP_TWDOG_MAP_CMD, 0, 0, 0,
				       0);
}

struct ffa_value sp_twdog_map_cmd(ffa_id_t source);

/**
 * Request SP to return the last serviced secure virtual interrupt.
 *
 * The command id is the hex representaton of the string "vINT".
 */
#define SP_LAST_INTERRUPT_SERVICED_CMD 0x76494e54U

static inline struct ffa_value sp_get_last_interrupt_cmd_send(ffa_id_t source,
							      ffa_id_t dest)
{
	return ffa_msg_send_direct_req(
		source, dest, SP_LAST_INTERRUPT_SERVICED_CMD, 0, 0, 0, 0);
}

struct ffa_value sp_get_last_interrupt_cmd(ffa_id_t source);

/**
 * Request SP to clear the last serviced secure virtual interrupt.
 */
#define SP_CLEAR_LAST_INTERRUPT_CMD (SP_LAST_INTERRUPT_SERVICED_CMD + 1)

static inline struct ffa_value sp_clear_last_interrupt_cmd_send(ffa_id_t source,
								ffa_id_t dest)
{
	return ffa_msg_send_direct_req(source, dest,
				       SP_CLEAR_LAST_INTERRUPT_CMD, 0, 0, 0, 0);
}

struct ffa_value sp_clear_last_interrupt_cmd(ffa_id_t source);

/**
 * Command to request SP to sleep for the given time in ms.
 *
 * The command id is the hex representation of string "slep".
 */
#define SP_SLEEP_CMD 0x736c6570U

static inline struct ffa_value sp_sleep_cmd_send(ffa_id_t source, ffa_id_t dest,
						 uint32_t sleep_time)
{
	return ffa_msg_send_direct_req(source, dest, SP_SLEEP_CMD, sleep_time,
				       0, 0, 0);
}

struct ffa_value sp_sleep_cmd(ffa_id_t source, uint32_t sleep_ms);

/**
 * Command to request SP to forward sleep command for the given time in ms.
 *
 * The sender of this command expects to receive SP_SUCCESS if the request to
 * forward sleep command was handled successfully, or SP_ERROR otherwise.
 * Moreover, the sender can send a hint to the destination SP to expect that
 * the forwaded sleep command could be preempted by a non-secure interrupt.
 */
#define SP_FWD_SLEEP_CMD (SP_SLEEP_CMD + 1)

static inline struct ffa_value sp_fwd_sleep_cmd_send(ffa_id_t source,
						     ffa_id_t dest,
						     ffa_id_t fwd_dest,
						     uint32_t busy_wait,
						     bool hint_interrupted)
{
	return ffa_msg_send_direct_req(source, dest, SP_FWD_SLEEP_CMD,
				       busy_wait, fwd_dest, hint_interrupted,
				       0);
}

static inline uint32_t sp_get_sleep_time(struct ffa_value ret)
{
	return (uint32_t)ret.arg4;
}

static inline ffa_id_t sp_get_fwd_sleep_dest(struct ffa_value ret)
{
	return (ffa_id_t)ret.arg5;
}

static inline bool sp_get_fwd_sleep_interrupted_hint(struct ffa_value ret)
{
	return (bool)ret.arg6;
}

struct ffa_value sp_fwd_sleep_cmd(ffa_id_t source, uint32_t sleep_ms,
				  ffa_id_t fwd_dest, bool hint_interrupted);

/**
 * Command to request SP to resume the task requested by current endpoint after
 * managed exit.
 *
 * The command id is the hex representation of the string "RAME" which denotes
 * (R)esume (A)fter (M)anaged (E)xit.
 */
#define SP_RESUME_AFTER_MANAGED_EXIT 0x52414d45U

static inline struct ffa_value sp_resume_after_managed_exit_send(
	ffa_id_t source, ffa_id_t dest)
{
	return ffa_msg_send_direct_req(
		source, dest, SP_RESUME_AFTER_MANAGED_EXIT, 0, 0, 0, 0);
}

static inline void sp_wait_loop(uint32_t iterations)
{
	for (volatile uint64_t loop = 0; loop < iterations; loop++) {
		/* Wait */
	}
}

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
 * Command to request an SP to yield while handling a secure interrupt.
 * The command id is the hex representaton of the string "YSIH".
 */
#define SP_YIELD_SEC_INTERRUPT_HANDLING_CMD 0x59534948U

static inline struct ffa_value sp_yield_secure_interrupt_handling_cmd_send(
	ffa_id_t source, ffa_id_t dest, bool yield)
{
	return ffa_msg_send_direct_req(source, dest,
				       SP_YIELD_SEC_INTERRUPT_HANDLING_CMD,
				       yield, 0, 0, 0);
}

struct ffa_value sp_yield_secure_interrupt_handling_cmd(ffa_id_t source,
							bool yield);

/**
 * Command to request an SP to reconfigure the secure interrupt to be targetted
 * to a given vCPU identified by its linear id.
 * The command id is the hex representaton of the string "RSTV".
 */
#define SP_ROUTE_SEC_INT_TARGET_VCPU_CMD 0x52535456U

static inline struct ffa_value sp_route_interrupt_to_target_vcpu_cmd_send(
	ffa_id_t source, ffa_id_t dest, ffa_vcpu_index_t target_vcpu_id,
	uint32_t int_id)
{
	return ffa_msg_send_direct_req(source, dest,
				       SP_ROUTE_SEC_INT_TARGET_VCPU_CMD,
				       target_vcpu_id, int_id, 0, 0);
}

struct ffa_value sp_route_interrupt_to_target_vcpu_cmd(
	ffa_id_t source, ffa_vcpu_index_t target_vcpu_id, uint32_t int_id);

/**
 * Command to request SP to pend an interrupt in the extended SPI range.
 * The command is the hex representation of the string "espi".
 */
#define SP_TRIGGER_ESPI_CMD 0x65737069U

static inline struct ffa_value sp_trigger_espi_cmd_send(ffa_id_t source,
							ffa_id_t dest,
							uint32_t espi_id)
{
	return ffa_msg_send_direct_req(source, dest, SP_TRIGGER_ESPI_CMD,
				       espi_id, 0, 0, 0);
}

struct ffa_value sp_trigger_espi_cmd(ffa_id_t source, uint32_t espi_id);
