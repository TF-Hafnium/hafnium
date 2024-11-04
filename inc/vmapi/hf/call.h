/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/abi.h"
#include "hf/ffa.h"
#include "hf/types.h"

/**
 * This function must be implemented to trigger the architecture-specific
 * mechanism to call to the hypervisor.
 */
int64_t hf_call(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);
struct ffa_value ffa_call(struct ffa_value args);
struct ffa_value ffa_call_ext(struct ffa_value args);
/* NOLINTNEXTLINE(readability-redundant-declaration) */
void memcpy_s(void *dest, size_t destsz, const void *src, size_t count);

/**
 * Returns the VM's own ID.
 */
static inline struct ffa_value ffa_id_get(void)
{
	return ffa_call((struct ffa_value){.func = FFA_ID_GET_32});
}

/**
 * Returns the SPMC FF-A ID at NS virtual/physical and secure virtual
 * FF-A instances.
 * DEN0077A FF-A v1.1 Beta0 section 13.9 FFA_SPM_ID_GET.
 */
static inline struct ffa_value ffa_spm_id_get(void)
{
	return ffa_call((struct ffa_value){.func = FFA_SPM_ID_GET_32});
}

/**
 * Requests information for partitions instantiated in the system via registers
 * (as opposed to rx buffer in the case of ffa_partition_info_get).
 */
static inline struct ffa_value ffa_partition_info_get_regs(
	const struct ffa_uuid *uuid, const uint16_t start_index,
	const uint16_t tag)
{
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3 = start_index | (uint64_t)tag << 16;

	ffa_uuid_to_u64x2(&arg1, &arg2, uuid);
	return ffa_call_ext((struct ffa_value){
		.func = FFA_PARTITION_INFO_GET_REGS_64,
		.arg1 = arg1,
		.arg2 = arg2,
		.arg3 = arg3,
	});
}

/**
 * Requests information for partitions instantiated in the system. If the
 * FFA_PARTITION_COUNT_FLAG is not set, the information is returned
 * in the RX buffer of the caller as an array of partition information
 * descriptors (struct ffa_partition_info).
 *
 * A Null UUID (UUID that is all zeros) returns information for all partitions,
 * whereas a non-Null UUID returns information only for partitions that match.
 *
 * Flags may include:
 *  - FFA_PARTITION_COUNT_FLAG, which specifes if the partition info descriptors
 *    are returned in RX buffer or just the count in arg2.
 *    1 returns just the count.
 *    0 returns the count with the partition info descriptors.
 *
 * Returns:
 *  - FFA_SUCCESS on success. The count of partition information descriptors
 *    populated in the RX buffer is returned in arg2 (register w2).
 *  - FFA_BUSY if the caller's RX buffer is not free.
 *  - FFA_NO_MEMORY if the results do not fit in the callers RX buffer.
 *  - FFA_INVALID_PARAMETERS for an unrecognized UUID.
 */
static inline struct ffa_value ffa_partition_info_get(
	const struct ffa_uuid *uuid, const uint32_t flags)
{
	return ffa_call((struct ffa_value){.func = FFA_PARTITION_INFO_GET_32,
					   .arg1 = uuid->uuid[0],
					   .arg2 = uuid->uuid[1],
					   .arg3 = uuid->uuid[2],
					   .arg4 = uuid->uuid[3],
					   .arg5 = flags});
}
/**
 * DEN0077A FF-A v1.1 Beta0 section 18.3.2.1
 * Registers vCPU secondary entry point for the caller VM.
 * Called from secure virtual FF-A instance.
 */
static inline struct ffa_value ffa_secondary_ep_register(uintptr_t address)
{
	return ffa_call((struct ffa_value){.func = FFA_SECONDARY_EP_REGISTER_64,
					   .arg1 = address});
}

/**
 * Returns the VM's own ID.
 */
static inline ffa_id_t hf_vm_get_id(void)
{
	return ffa_id_get().arg2;
}

/**
 * Runs the given vCPU of the given VM.
 */
static inline struct ffa_value ffa_run(ffa_id_t vm_id,
				       ffa_vcpu_index_t vcpu_idx)
{
	return ffa_call_ext((struct ffa_value){.func = FFA_RUN_32,
					       ffa_vm_vcpu(vm_id, vcpu_idx)});
}

/**
 * Hints that the vCPU is willing to yield its current use of the physical CPU
 * and intends to be resumed at the expiration of the timeout.
 */
static inline struct ffa_value ffa_yield_timeout(uint32_t timeout_low,
						 uint32_t timeout_high)
{
	return ffa_call((struct ffa_value){.func = FFA_YIELD_32,
					   .arg2 = timeout_low,
					   .arg3 = timeout_high});
}

/**
 * Relinquish the current physical CPU cycles back.
 */
static inline struct ffa_value ffa_yield(void)
{
	return ffa_yield_timeout(0, 0);
}

/**
 * Configures the pages to send/receive data through. The pages must not be
 * shared.
 *
 * Returns:
 *  - FFA_ERROR FFA_INVALID_PARAMETERS if the given addresses are not properly
 *    aligned or are the same.
 *  - FFA_ERROR FFA_NO_MEMORY if the hypervisor was unable to map the buffers
 *    due to insufficient page table memory.
 *  - FFA_ERROR FFA_DENIED if the pages are already mapped or are not owned by
 *    the caller.
 *  - FFA_SUCCESS on success if no further action is needed.
 *  - FFA_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters.
 */
static inline struct ffa_value ffa_rxtx_map(hf_ipaddr_t send, hf_ipaddr_t recv)
{
	return ffa_call(
		(struct ffa_value){.func = FFA_RXTX_MAP_64,
				   .arg1 = send,
				   .arg2 = recv,
				   .arg3 = HF_MAILBOX_SIZE / FFA_PAGE_SIZE});
}

/**
 * Unmaps the RX/TX buffer pair of an endpoint or Hypervisor from the
 * translation regime of the callee.
 *
 * Returns:
 *   - FFA_ERROR FFA_INVALID_PARAMETERS if there is no buffer pair registered on
 *     behalf of the caller.
 *   - FFA_SUCCESS on success if no further action is needed.
 */
static inline struct ffa_value ffa_rxtx_unmap(void)
{
	/* Note that allocator ID MBZ at virtual instance. */
	return ffa_call((struct ffa_value){.func = FFA_RXTX_UNMAP_32});
}

/**
 * Copies data from the sender's send buffer to the recipient's receive buffer.
 *
 * If the recipient's receive buffer is busy, it can optionally register the
 * caller to be notified when the recipient's receive buffer becomes available.
 *
 * Attributes may include:
 *  - FFA_MSG_SEND_NOTIFY, to notify the caller when it should try again.
 *  - FFA_MSG_SEND_LEGACY_MEMORY_*, to send a legacy architected memory sharing
 *    message.
 *
 * Returns FFA_SUCCESS if the message is sent, or an error code otherwise:
 *  - INVALID_PARAMETERS: one or more of the parameters do not conform.
 *  - BUSY: the message could not be delivered either because the mailbox
 *    was full or the target VM is not yet set up.
 */
static inline struct ffa_value ffa_msg_send(ffa_id_t sender_vm_id,
					    ffa_id_t target_vm_id,
					    uint32_t size, uint32_t attributes)
{
	return ffa_call((struct ffa_value){
		.func = FFA_MSG_SEND_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg3 = size,
		.arg4 = attributes});
}

/**
 * Copies data from the sender's send buffer to the recipient's receive buffer
 * and notifies the receiver.
 *
 * `flags` may include a 'Delay Schedule Receiver interrupt'.
 *
 * Returns FFA_SUCCESS if the message is sent, or an error code otherwise:
 *  - INVALID_PARAMETERS: one or more of the parameters do not conform.
 *  - BUSY: receiver's mailbox was full.
 *  - DENIED: receiver is not in a state to handle the request or doesn't
 *    support indirect messages.
 */
static inline struct ffa_value ffa_msg_send2(uint32_t flags)
{
	return ffa_call((struct ffa_value){
		.func = FFA_MSG_SEND2_32, .arg1 = 0, .arg2 = flags});
}

static inline struct ffa_value ffa_mem_donate(uint32_t length,
					      uint32_t fragment_length)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_DONATE_32,
					   .arg1 = length,
					   .arg2 = fragment_length});
}

static inline struct ffa_value ffa_mem_lend(uint32_t length,
					    uint32_t fragment_length)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_LEND_32,
					   .arg1 = length,
					   .arg2 = fragment_length});
}

static inline struct ffa_value ffa_mem_share(uint32_t length,
					     uint32_t fragment_length)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_SHARE_32,
					   .arg1 = length,
					   .arg2 = fragment_length});
}

static inline struct ffa_value ffa_mem_retrieve_req(uint32_t length,
						    uint32_t fragment_length)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_RETRIEVE_REQ_32,
					   .arg1 = length,
					   .arg2 = fragment_length});
}

static inline struct ffa_value ffa_mem_relinquish(void)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_RELINQUISH_32});
}

static inline struct ffa_value ffa_mem_reclaim(ffa_memory_handle_t handle,
					       ffa_memory_region_flags_t flags)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_RECLAIM_32,
					   .arg1 = (uint32_t)handle,
					   .arg2 = (uint32_t)(handle >> 32),
					   .arg3 = flags});
}

static inline struct ffa_value ffa_mem_frag_rx(ffa_memory_handle_t handle,
					       uint32_t fragment_offset)
{
	/* Note that sender MBZ at virtual instance. */
	return ffa_call((struct ffa_value){.func = FFA_MEM_FRAG_RX_32,
					   .arg1 = (uint32_t)handle,
					   .arg2 = (uint32_t)(handle >> 32),
					   .arg3 = fragment_offset});
}

static inline struct ffa_value ffa_mem_frag_tx(ffa_memory_handle_t handle,
					       uint32_t fragment_length)
{
	/* Note that sender MBZ at virtual instance. */
	return ffa_call((struct ffa_value){.func = FFA_MEM_FRAG_TX_32,
					   .arg1 = (uint32_t)handle,
					   .arg2 = (uint32_t)(handle >> 32),
					   .arg3 = fragment_length});
}

/**
 * Called by secondary VMs to receive a message. This will block until a message
 * is received.
 *
 * The mailbox must be cleared before a new message can be received.
 *
 * By default, FFA_MSG_WAIT will release the mailbox back to the SPMC. The
 * FFA_MSG_WAIT_FLAG_RETAIN_RX flag can be used with `ffa_msg_wait_with_flags`
 * function to override this default and allow the VM to retain the RX buffer.
 *
 * If no message is immediately available and there are no enabled and pending
 * interrupts (irrespective of whether interrupts are enabled globally), then
 * this will block until a message is available or an enabled interrupt becomes
 * pending. This matches the behaviour of the WFI instruction on AArch64, except
 * that a message becoming available is also treated like a wake-up event.
 *
 * Returns:
 *  - FFA_ERROR FFA_NOT_SUPPORTED if called from the primary VM.
 *  - FFA_ERROR FFA_INTERRUPTED if an interrupt happened during the call.
 */
static inline struct ffa_value ffa_msg_wait_with_flags(uint32_t flags)
{
	return ffa_call_ext(
		(struct ffa_value){.func = FFA_MSG_WAIT_32, .arg2 = flags});
}

static inline struct ffa_value ffa_msg_wait(void)
{
	return ffa_msg_wait_with_flags(0);
}

/**
 * Called by secondary VMs to receive a message. The call will return whether or
 * not a message is available.
 *
 * The mailbox must be cleared before a new message can be received.
 *
 * Returns:
 *  - FFA_MSG_SEND if a message is successfully received.
 *  - FFA_ERROR FFA_NOT_SUPPORTED if called from the primary VM.
 *  - FFA_ERROR FFA_INTERRUPTED if an interrupt happened during the call.
 *  - FFA_ERROR FFA_RETRY if there was no pending message.
 */
static inline struct ffa_value ffa_msg_poll(void)
{
	return ffa_call((struct ffa_value){.func = FFA_MSG_POLL_32});
}

/**
 * Releases the caller's mailbox so that a new message can be received. The
 * caller must have copied out all data they wish to preserve as new messages
 * will overwrite the old and will arrive asynchronously.
 *
 * Returns:
 *  - FFA_ERROR FFA_DENIED on failure, if the mailbox hasn't been read.
 *  - FFA_SUCCESS on success if no further action is needed.
 *  - FFA_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters. Waiters should be retrieved by calling
 *    hf_mailbox_waiter_get.
 */
static inline struct ffa_value ffa_rx_release(void)
{
	return ffa_call((struct ffa_value){.func = FFA_RX_RELEASE_32});
}

/**
 * Enables or disables a given interrupt ID.
 *
 * Returns 0 on success, or -1 if the intid is invalid.
 */
static inline int64_t hf_interrupt_enable(uint32_t intid, bool enable,
					  uint32_t type)
{
	return hf_call(HF_INTERRUPT_ENABLE, intid, enable, type);
}

/**
 * Gets the ID of the pending interrupt (if any) and acknowledge it.
 *
 * Returns HF_INVALID_INTID if there are no pending interrupts.
 */
static inline uint32_t hf_interrupt_get(void)
{
	return hf_call(HF_INTERRUPT_GET, 0, 0, 0);
}

/**
 * Deactivate the physical interrupt.
 *
 * Returns 0 on success, or -1 otherwise.
 */
static inline int64_t hf_interrupt_deactivate(uint32_t intid)
{
	return hf_call(HF_INTERRUPT_DEACTIVATE, intid, intid, 0);
}

/**
 * Reconfigure the virtual interrupt belonging to the current SP. Note that the
 * virtual interrupt is identity mapped to the physical interrupt id.
 *
 * Returns -1 on failure, or 0 on success.
 */
static inline int64_t hf_interrupt_reconfigure(uint32_t intid, uint32_t command,
					       uint32_t value)
{
	return hf_call(HF_INTERRUPT_RECONFIGURE, intid, command, value);
}

static inline int64_t hf_interrupt_reconfigure_target_cpu(
	uint32_t intid, ffa_vcpu_index_t target_cpu_index)
{
	return hf_interrupt_reconfigure(intid, INT_RECONFIGURE_TARGET_PE,
					(uint32_t)target_cpu_index);
}

/**
 * Trigger an IPI to target vcpu.
 */
static inline int64_t hf_interrupt_send_ipi(ffa_vcpu_index_t target_vcpu_id)
{
	return hf_call(HF_INTERRUPT_SEND_IPI, (uint64_t)target_vcpu_id, 0, 0);
}

/** Obtains the Hafnium's version of the implemented FF-A specification. */
static inline enum ffa_version ffa_version(enum ffa_version requested_version)
{
	return ffa_call((struct ffa_value){
				.func = FFA_VERSION_32,
				.arg1 = (uint32_t)requested_version,
			})
		.func;
}

/**
 * Discovery function returning information about the implementation of optional
 * FF-A interfaces.
 *
 * Returns:
 *  - FFA_SUCCESS in .func if the optional interface with function_id is
 * implemented.
 *  - FFA_ERROR in .func if the optional interface with function_id is not
 * implemented.
 */
static inline struct ffa_value ffa_features(uint64_t function_id)
{
	return ffa_call((struct ffa_value){
		.func = FFA_FEATURES_32,
		.arg1 = function_id,
	});
}

/**
 * Discovery function returning information about the implementation of optional
 * FF-A interfaces which require an extra input property
 *
 * Returns:
 *  - FFA_SUCCESS in .func if the optional interface with function_id is
 * implemented.
 *  - FFA_ERROR in .func if the optional interface with function_id is not
 * implemented.
 */
static inline struct ffa_value ffa_features_with_input_property(
	uint64_t function_id, uint64_t param)
{
	return ffa_call((struct ffa_value){
		.func = FFA_FEATURES_32, .arg1 = function_id, .arg2 = param});
}

static inline struct ffa_value ffa_msg_send_direct_req(
	ffa_id_t sender_vm_id, ffa_id_t target_vm_id, uint32_t arg3,
	uint32_t arg4, uint32_t arg5, uint32_t arg6, uint32_t arg7)
{
	return ffa_call((struct ffa_value){
		.func = FFA_MSG_SEND_DIRECT_REQ_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg2 = 0,
		.arg3 = arg3,
		.arg4 = arg4,
		.arg5 = arg5,
		.arg6 = arg6,
		.arg7 = arg7,
	});
}

static inline struct ffa_value ffa_framework_msg_send_direct_req(
	ffa_id_t sender_vm_id, ffa_id_t target_vm_id, uint32_t func,
	ffa_id_t vm_id)
{
	return ffa_call((struct ffa_value){
		.func = FFA_MSG_SEND_DIRECT_REQ_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg2 = FFA_FRAMEWORK_MSG_BIT | func,
		.arg5 = vm_id,
	});
}

/** Create an `ffa_value` suitable for the response to a framework message. */
static inline struct ffa_value ffa_framework_msg_resp(ffa_id_t sender_vm_id,
						      ffa_id_t receiver_vm_id,
						      uint32_t func,
						      uint64_t arg3)
{
	return (struct ffa_value){
		.func = FFA_MSG_SEND_DIRECT_RESP_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | receiver_vm_id,
		/* Set bit 31 since this is a framework message. */
		.arg2 = FFA_FRAMEWORK_MSG_BIT | func,
		.arg3 = arg3,
	};
}

static inline struct ffa_value ffa_msg_send_direct_req2(
	ffa_id_t sender_vm_id, ffa_id_t target_vm_id,
	const struct ffa_uuid *uuid, const uint64_t *msg, size_t count)
{
	struct ffa_value args;
	size_t arg_idx = 0;
	uint64_t total_args;
	size_t msg_idx = 0;
	uint64_t *arg_ptrs[] = {
		&args.arg4,
		&args.arg5,
		&args.arg6,
		&args.arg7,
		&args.extended_val.arg8,
		&args.extended_val.arg9,
		&args.extended_val.arg10,
		&args.extended_val.arg11,
		&args.extended_val.arg12,
		&args.extended_val.arg13,
		&args.extended_val.arg14,
		&args.extended_val.arg15,
		&args.extended_val.arg16,
		&args.extended_val.arg17,
	};

	args.func = FFA_MSG_SEND_DIRECT_REQ2_64;
	args.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id;
	ffa_uuid_to_u64x2(&args.arg2, &args.arg3, uuid);

	total_args = (sizeof(arg_ptrs) / sizeof(uint64_t *));

	while (arg_idx < total_args && msg_idx < count) {
		*arg_ptrs[arg_idx++] = msg[msg_idx++];
	}

	while (arg_idx < total_args) {
		*arg_ptrs[arg_idx++] = 0;
	}

	return ffa_call_ext(args);
}

static inline struct ffa_value ffa_msg_send_direct_resp(
	ffa_id_t sender_vm_id, ffa_id_t target_vm_id, uint32_t arg3,
	uint32_t arg4, uint32_t arg5, uint32_t arg6, uint32_t arg7)
{
	return ffa_call_ext((struct ffa_value){
		.func = FFA_MSG_SEND_DIRECT_RESP_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg3 = arg3,
		.arg4 = arg4,
		.arg5 = arg5,
		.arg6 = arg6,
		.arg7 = arg7,
	});
}

static inline struct ffa_value ffa_framework_message_send_direct_resp(
	ffa_id_t sender_vm_id, ffa_id_t target_vm_id, uint32_t func,
	uint32_t arg3)
{
	return ffa_call_ext(
		ffa_framework_msg_resp(sender_vm_id, target_vm_id, func, arg3));
}

static inline struct ffa_value ffa_msg_send_direct_resp2(ffa_id_t sender_vm_id,
							 ffa_id_t target_vm_id,
							 const uint64_t *msg,
							 size_t count)
{
	struct ffa_value args;
	size_t arg_idx = 0;
	size_t total_args;
	size_t msg_idx = 0;
	uint64_t *arg_ptrs[] = {
		&args.arg4,
		&args.arg5,
		&args.arg6,
		&args.arg7,
		&args.extended_val.arg8,
		&args.extended_val.arg9,
		&args.extended_val.arg10,
		&args.extended_val.arg11,
		&args.extended_val.arg12,
		&args.extended_val.arg13,
		&args.extended_val.arg14,
		&args.extended_val.arg15,
		&args.extended_val.arg16,
		&args.extended_val.arg17,
	};

	args.func = FFA_MSG_SEND_DIRECT_RESP2_64;
	args.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id;
	args.arg2 = 0;
	args.arg3 = 0;

	total_args = sizeof(arg_ptrs) / sizeof(uint64_t *);

	while (arg_idx < total_args && msg_idx < count) {
		*arg_ptrs[arg_idx++] = msg[msg_idx++];
	}

	while (arg_idx < total_args) {
		*arg_ptrs[arg_idx++] = 0;
	}

	return ffa_call_ext(args);
}

static inline struct ffa_value ffa_notification_bind(
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap)
{
	return ffa_call((struct ffa_value){
		.func = FFA_NOTIFICATION_BIND_32,
		.arg1 = (sender_vm_id << 16) | (receiver_vm_id),
		.arg2 = flags,
		.arg3 = (uint32_t)(bitmap),
		.arg4 = (uint32_t)(bitmap >> 32),
	});
}

static inline struct ffa_value ffa_notification_unbind(
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id,
	ffa_notifications_bitmap_t bitmap)
{
	return ffa_call((struct ffa_value){
		.func = FFA_NOTIFICATION_UNBIND_32,
		.arg1 = (sender_vm_id << 16) | (receiver_vm_id),
		.arg3 = (uint32_t)(bitmap),
		.arg4 = (uint32_t)(bitmap >> 32),
	});
}

static inline struct ffa_value ffa_notification_set(
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap)
{
	return ffa_call((struct ffa_value){
		.func = FFA_NOTIFICATION_SET_32,
		.arg1 = (sender_vm_id << 16) | (receiver_vm_id),
		.arg2 = flags,
		.arg3 = (uint32_t)(bitmap),
		.arg4 = (uint32_t)(bitmap >> 32),
	});
}

static inline struct ffa_value ffa_notification_get(ffa_id_t receiver_vm_id,
						    ffa_vcpu_index_t vcpu_id,
						    uint32_t flags)
{
	return ffa_call((struct ffa_value){
		.func = FFA_NOTIFICATION_GET_32,
		.arg1 = (vcpu_id << 16) | (receiver_vm_id),
		.arg2 = flags,
	});
}

static inline struct ffa_value ffa_notification_info_get(void)
{
	return ffa_call((struct ffa_value){
		.func = FFA_NOTIFICATION_INFO_GET_64,
	});
}

static inline struct ffa_value ffa_mem_perm_get(uint64_t base_va)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_PERM_GET_32,
					   .arg1 = base_va});
}

static inline struct ffa_value ffa_mem_perm_set(uint64_t base_va,
						uint32_t page_count,
						uint32_t mem_perm)
{
	return ffa_call((struct ffa_value){.func = FFA_MEM_PERM_SET_32,
					   .arg1 = base_va,
					   .arg2 = page_count,
					   .arg3 = mem_perm});
}

static inline struct ffa_value ffa_console_log_32(const char *src, size_t size)
{
	struct ffa_value req = {
		.func = FFA_CONSOLE_LOG_32,
		.arg1 = size,
	};

	uint64_t *arg_addrs[] = {&req.arg2, &req.arg3, &req.arg4,
				 &req.arg5, &req.arg6, &req.arg7};

	uint32_t src_index = 0;
	uint32_t arg_idx = 0;

	while (size > 0 && arg_idx < 6) {
		size_t arg_size =
			size < sizeof(uint32_t) ? size : sizeof(uint32_t);
		memcpy_s(arg_addrs[arg_idx++], sizeof(uint32_t),
			 &src[src_index], arg_size);
		src_index += arg_size;
		size -= arg_size;
	}

	return ffa_call(req);
}

static inline struct ffa_value ffa_console_log_64(const char *src, size_t size)
{
	struct ffa_value req = {
		.func = FFA_CONSOLE_LOG_64,
		.arg1 = size,
	};
	const size_t destsz = sizeof(uint64_t) * 6;
	const size_t count = size > destsz ? destsz : size;

	memcpy_s(&req.arg2, destsz, src, count);

	return ffa_call(req);
}

static inline struct ffa_value ffa_console_log_64_extended(const char *src,
							   size_t size)
{
	struct ffa_value req = {
		.func = FFA_CONSOLE_LOG_64,
		.arg1 = size,
	};
	const size_t destsz = sizeof(uint64_t) * 16;
	const size_t count = size > destsz ? destsz : size;

	memcpy_s(&req.arg2, destsz, src, count);

	return ffa_call_ext(req);
}
