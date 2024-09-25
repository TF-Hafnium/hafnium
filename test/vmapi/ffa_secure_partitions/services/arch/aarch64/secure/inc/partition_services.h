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
#define SP_ERROR (-1)

/* Various fields encoded in `options` parameter. */
#define OPTIONS_MASK_INTERRUPTS (1 << 0)
#define OPTIONS_HINT_INTERRUPTED (1 << 1)
#define OPTIONS_YIELD_DIR_REQ (1 << 2)

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

static inline uint32_t sp_resp_value(struct ffa_value res)
{
	return res.arg4;
}

ffa_id_t sp_find_next_endpoint(ffa_id_t self_id);

enum sp_cmd {
	/**
	 * Command to request SP to echo payload back to the sender.
	 */
	SP_ECHO_CMD = 1,

	/**
	 * Command to request SP to run echo test with second SP.
	 */
	SP_REQ_ECHO_CMD,

	/**
	 * Command to request SP to run echo busy test with second SP.
	 */
	SP_REQ_ECHO_BUSY_CMD,

	/**
	 * Command to request SP to set notifications.
	 */
	SP_NOTIF_SET_CMD,

	/**
	 * Command to request SP to get notifications.
	 */
	SP_NOTIF_GET_CMD,

	/**
	 * Command to request SP to bind notifications to the specified sender.
	 */
	SP_NOTIF_BIND_CMD,

	/**
	 * Command to request SP to unbind notifications from the specified
	 * sender.
	 */
	SP_NOTIF_UNBIND_CMD,

	/**
	 * Command to request SP to validate if core index passed to the SP is
	 * as expected.
	 */
	SP_CHECK_CPU_IDX_CMD,

	/**
	 * Command to request SP to actively wait in a busy loop.
	 */
	SP_WAIT_BUSY_LOOP_CMD,

	/**
	 * Command to request an SP to perform various state transitions through
	 * FF-A ABIs.
	 */
	SP_CHECK_STATE_TRANSITIONS_CMD,

	/**
	 * Command to request SP to enable/disable a secure virtual interrupt.
	 */
	SP_VIRTUAL_INTERRUPT_CMD,

	/**
	 * Request to start trusted watchdog timer.
	 */
	SP_TWDOG_START_CMD,

	/**
	 * Request SP to return the last serviced secure virtual interrupt.
	 */
	SP_LAST_INTERRUPT_SERVICED_CMD,

	/**
	 * Request SP to clear the last serviced secure virtual interrupt.
	 */
	SP_CLEAR_LAST_INTERRUPT_CMD,

	/**
	 * Command to request SP to sleep for the given time in ms.
	 */
	SP_SLEEP_CMD,

	/**
	 * Command to request SP to forward sleep command for the given time in
	 * ms.
	 *
	 * The sender of this command expects to receive SP_SUCCESS if the
	 * request to forward sleep command was handled successfully, or
	 * SP_ERROR otherwise. Moreover, the sender can send a hint to the
	 * destination SP to expect that the forwaded sleep command could be
	 * preempted by a non-secure interrupt.
	 */
	SP_FWD_SLEEP_CMD,

	/**
	 * Command to request SP to resume the task requested by current
	 * endpoint after managed exit.
	 */
	SP_RESUME_AFTER_MANAGED_EXIT,

	/**
	 * Command to request an SP to perform checks using
	 * ffa_partition_info_get_regs ABI.
	 */
	SP_CHECK_PARTITION_INFO_GET_REGS_CMD,

	/**
	 * Command to request an SP to yield while handling a secure interrupt.
	 */
	SP_YIELD_SEC_INTERRUPT_HANDLING_CMD,

	/**
	 * Command to request an SP to prepare to initiate an SPMC call chain.
	 */
	SP_PREPARE_SPMC_CALL_CHAIN_CMD,

	/**
	 * Command to request an SP to prepare to preempt itself while handling
	 * a virtual interrupt.
	 */
	SP_PREPARE_PREEMPT_INT_HANDLING,

	/**
	 * Command to request an SP to reconfigure the secure interrupt to be
	 * targetted to a given vCPU identified by its linear id.
	 */
	SP_ROUTE_SEC_INT_TARGET_VCPU_CMD,

	/**
	 * Command to request SP to pend an interrupt in the extended SPI range.
	 */
	SP_TRIGGER_ESPI_CMD,

	SP_FFA_FEATURES_CMD,
	SP_FFA_MEM_RETRIEVE_CMD,

	/**
	 * Request to start generic timer.
	 */
	SP_GENERIC_TIMER_START_CMD,
	SP_PAUTH_FAULT_CMD,

	/**
	 * Request to start arch timer and sleep as necessary.
	 */
	SP_ARCH_TIMER_CMD,
};

/**
 * Command to request SP to echo payload back to the sender.
 */
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
 * Command to request SP to run echo busy test with second SP.
 */
static inline struct ffa_value sp_req_echo_busy_cmd_send(ffa_id_t sender,
							 ffa_id_t receiver)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_REQ_ECHO_BUSY_CMD,
				       0, 0, 0, 0);
}

struct ffa_value sp_req_echo_busy_cmd(ffa_id_t test_source);

/**
 * Command to request SP to set notifications.
 */
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
 */
static inline struct ffa_value sp_twdog_cmd_send(ffa_id_t source, ffa_id_t dest,
						 uint64_t time)
{
	return ffa_msg_send_direct_req(source, dest, SP_TWDOG_START_CMD, time,
				       0, 0, 0);
}

struct ffa_value sp_twdog_cmd(ffa_id_t source, uint64_t time);

/**
 * Request SP to return the last serviced secure virtual interrupt.
 */
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
static inline struct ffa_value sp_clear_last_interrupt_cmd_send(ffa_id_t source,
								ffa_id_t dest)
{
	return ffa_msg_send_direct_req(source, dest,
				       SP_CLEAR_LAST_INTERRUPT_CMD, 0, 0, 0, 0);
}

struct ffa_value sp_clear_last_interrupt_cmd(ffa_id_t source);

/**
 * Command to request SP to sleep for the given time in ms.
 */
static inline struct ffa_value sp_sleep_cmd_send(ffa_id_t source, ffa_id_t dest,
						 uint32_t sleep_time,
						 uint32_t options)
{
	return ffa_msg_send_direct_req(source, dest, SP_SLEEP_CMD, sleep_time,
				       options, 0, 0);
}

struct ffa_value sp_sleep_cmd(ffa_id_t source, uint32_t sleep_ms,
			      uint32_t options, uint64_t func);

static inline uint32_t sp_get_sleep_options(struct ffa_value ret)
{
	return (uint32_t)ret.arg5;
}

/**
 * Command to request SP to forward sleep command for the given time in ms.
 *
 * The sender of this command expects to receive SP_SUCCESS if the request to
 * forward sleep command was handled successfully, or SP_ERROR otherwise.
 * Moreover, the sender can send a hint to the destination SP to expect that
 * the forwaded sleep command could be preempted by a non-secure interrupt.
 */
static inline struct ffa_value sp_fwd_sleep_cmd_send(ffa_id_t source,
						     ffa_id_t dest,
						     ffa_id_t fwd_dest,
						     uint32_t busy_wait,
						     uint32_t options)
{
	return ffa_msg_send_direct_req(source, dest, SP_FWD_SLEEP_CMD,
				       busy_wait, fwd_dest, options, 0);
}

static inline uint32_t sp_get_sleep_time(struct ffa_value ret)
{
	return (uint32_t)ret.arg4;
}

static inline ffa_id_t sp_get_fwd_sleep_dest(struct ffa_value ret)
{
	return (ffa_id_t)ret.arg5;
}

static inline uint32_t sp_get_fwd_sleep_options(struct ffa_value ret)
{
	return (uint32_t)ret.arg6;
}

struct ffa_value sp_fwd_sleep_cmd(ffa_id_t source, uint32_t sleep_ms,
				  ffa_id_t fwd_dest, uint32_t options);

/**
 * Command to request SP to resume the task requested by current endpoint after
 * managed exit.
 */
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
 */
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
 */
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
 */
static inline struct ffa_value sp_trigger_espi_cmd_send(ffa_id_t source,
							ffa_id_t dest,
							uint32_t espi_id)
{
	return ffa_msg_send_direct_req(source, dest, SP_TRIGGER_ESPI_CMD,
				       espi_id, 0, 0, 0);
}

struct ffa_value sp_trigger_espi_cmd(ffa_id_t source, uint32_t espi_id);

static inline struct ffa_value sp_ffa_features_cmd_send(
	ffa_id_t sender, ffa_id_t receiver, uint32_t feature_func_id)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_FFA_FEATURES_CMD,
				       feature_func_id, 0, 0, 0);
}

struct ffa_value sp_ffa_features_cmd(ffa_id_t source, uint32_t feature_func_id);

static inline struct ffa_value sp_ffa_mem_retrieve_cmd_send(
	ffa_id_t sender, ffa_id_t receiver, ffa_memory_handle_t handle,
	enum ffa_version ffa_version)
{
	return ffa_msg_send_direct_req(sender, receiver,
				       SP_FFA_MEM_RETRIEVE_CMD, handle,
				       ffa_version, 0, 0);
}

struct ffa_value sp_ffa_mem_retrieve_cmd(ffa_id_t sender_id,
					 ffa_memory_handle_t handle,
					 enum ffa_version ffa_version);

/**
 * Request to start generic timer.
 */
static inline struct ffa_value sp_generic_timer_cmd_send(ffa_id_t source,
							 ffa_id_t dest,
							 uint64_t time)
{
	return ffa_msg_send_direct_req(source, dest, SP_GENERIC_TIMER_START_CMD,
				       time, 0, 0, 0);
}

struct ffa_value sp_generic_timer_cmd(ffa_id_t source, uint64_t time);

static inline struct ffa_value sp_pauth_fault_cmd_send(ffa_id_t sender,
						       ffa_id_t receiver)
{
	return ffa_msg_send_direct_req(sender, receiver, SP_PAUTH_FAULT_CMD, 0,
				       0, 0, 0);
}

void sp_pauth_fault_cmd(void);

/**
 * Command to request an SP to prepare to initiate an SPMC call chain.
 */
static inline struct ffa_value sp_prepare_spmc_call_chain_cmd_send(
	ffa_id_t source, ffa_id_t dest, bool initiate)
{
	return ffa_msg_send_direct_req(source, dest,
				       SP_PREPARE_SPMC_CALL_CHAIN_CMD, initiate,
				       0, 0, 0);
}

struct ffa_value sp_prepare_spmc_call_chain_cmd(ffa_id_t source, bool initiate);

/**
 * Command to request an SP to prepare to preempt itself while handling a
 * virtual interrupt.
 */
static inline struct ffa_value sp_prepare_preempt_interrupt_handling_cmd_send(
	ffa_id_t source, ffa_id_t dest, bool preempt)
{
	return ffa_msg_send_direct_req(source, dest,
				       SP_PREPARE_PREEMPT_INT_HANDLING, preempt,
				       0, 0, 0);
}

struct ffa_value sp_prepare_preempt_interrupt_handling_cmd(ffa_id_t source,
							   bool preempt);

/**
 * Command to request SP to program timer with delay and sleep for the given
 * time in ms.
 */
static inline struct ffa_value sp_program_arch_timer_sleep_cmd_send(
	ffa_id_t source, ffa_id_t dest, uint32_t timer_delay,
	uint32_t sleep_time, uint32_t fwd)
{
	return ffa_msg_send_direct_req(source, dest, SP_ARCH_TIMER_CMD,
				       timer_delay, sleep_time, fwd, 0);
}

struct ffa_value sp_program_arch_timer_sleep_cmd(ffa_id_t source,
						 uint32_t timer_delay_ms,
						 uint32_t sleep_ms,
						 uint32_t fwd);

static inline uint32_t sp_get_arch_timer_delay(struct ffa_value ret)
{
	return (uint32_t)ret.arg4;
}

static inline uint32_t sp_get_arch_timer_sleep(struct ffa_value ret)
{
	return (uint32_t)ret.arg5;
}

static inline uint32_t sp_get_arch_timer_fwd_call(struct ffa_value ret)
{
	return (uint32_t)ret.arg6;
}
