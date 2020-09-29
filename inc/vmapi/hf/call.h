/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/abi.h"
#include "hf/spci.h"
#include "hf/types.h"

/**
 * This function must be implemented to trigger the architecture-specific
 * mechanism to call to the hypervisor.
 */
int64_t hf_call(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);
struct spci_value spci_call(struct spci_value args);

/**
 * Returns the VM's own ID.
 */
static inline struct spci_value spci_id_get(void)
{
	return spci_call((struct spci_value){.func = SPCI_ID_GET_32});
}

/**
 * Returns the VM's own ID.
 */
static inline spci_vm_id_t hf_vm_get_id(void)
{
	return spci_id_get().arg2;
}

/**
 * Returns the number of secondary VMs.
 */
static inline spci_vm_count_t hf_vm_get_count(void)
{
	return hf_call(HF_VM_GET_COUNT, 0, 0, 0);
}

/**
 * Returns the number of vCPUs configured in the given secondary VM.
 */
static inline spci_vcpu_count_t hf_vcpu_get_count(spci_vm_id_t vm_id)
{
	return hf_call(HF_VCPU_GET_COUNT, vm_id, 0, 0);
}

/**
 * Runs the given vCPU of the given VM.
 */
static inline struct spci_value spci_run(spci_vm_id_t vm_id,
					 spci_vcpu_index_t vcpu_idx)
{
	return spci_call((struct spci_value){.func = SPCI_RUN_32,
					     spci_vm_vcpu(vm_id, vcpu_idx)});
}

/**
 * Hints that the vCPU is willing to yield its current use of the physical CPU.
 * This call always returns SPCI_SUCCESS.
 */
static inline struct spci_value spci_yield(void)
{
	return spci_call((struct spci_value){.func = SPCI_YIELD_32});
}

/**
 * Configures the pages to send/receive data through. The pages must not be
 * shared.
 *
 * Returns:
 *  - SPCI_ERROR SPCI_INVALID_PARAMETERS if the given addresses are not properly
 *    aligned or are the same.
 *  - SPCI_ERROR SPCI_NO_MEMORY if the hypervisor was unable to map the buffers
 *    due to insuffient page table memory.
 *  - SPCI_ERROR SPCI_DENIED if the pages are already mapped or are not owned by
 *    the caller.
 *  - SPCI_SUCCESS on success if no further action is needed.
 *  - SPCI_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters.
 */
static inline struct spci_value spci_rxtx_map(hf_ipaddr_t send,
					      hf_ipaddr_t recv)
{
	return spci_call(
		(struct spci_value){.func = SPCI_RXTX_MAP_64,
				    .arg1 = send,
				    .arg2 = recv,
				    .arg3 = HF_MAILBOX_SIZE / SPCI_PAGE_SIZE});
}

/**
 * Copies data from the sender's send buffer to the recipient's receive buffer.
 *
 * If the recipient's receive buffer is busy, it can optionally register the
 * caller to be notified when the recipient's receive buffer becomes available.
 *
 * Attributes may include:
 *  - SPCI_MSG_SEND_NOTIFY, to notify the caller when it should try again.
 *  - SPCI_MSG_SEND_LEGACY_MEMORY_*, to send a legacy architected memory sharing
 *    message.
 *
 * Returns SPCI_SUCCESS if the message is sent, or an error code otherwise:
 *  - INVALID_PARAMETERS: one or more of the parameters do not conform.
 *  - BUSY: the message could not be delivered either because the mailbox
 *    was full or the target VM is not yet set up.
 */
static inline struct spci_value spci_msg_send(spci_vm_id_t sender_vm_id,
					      spci_vm_id_t target_vm_id,
					      uint32_t size,
					      uint32_t attributes)
{
	return spci_call((struct spci_value){
		.func = SPCI_MSG_SEND_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg3 = size,
		.arg4 = attributes});
}

static inline struct spci_value spci_mem_donate(uint32_t fragment_length,
						uint32_t length,
						uint32_t cookie)
{
	return spci_call((struct spci_value){.func = SPCI_MEM_DONATE_32,
					     .arg3 = fragment_length,
					     .arg4 = length,
					     .arg5 = cookie});
}

static inline struct spci_value spci_mem_lend(uint32_t fragment_length,
					      uint32_t length, uint32_t cookie)
{
	return spci_call((struct spci_value){.func = SPCI_MEM_LEND_32,
					     .arg3 = fragment_length,
					     .arg4 = length,
					     .arg5 = cookie});
}

static inline struct spci_value spci_mem_share(uint32_t fragment_length,
					       uint32_t length, uint32_t cookie)
{
	return spci_call((struct spci_value){.func = SPCI_MEM_SHARE_32,
					     .arg3 = fragment_length,
					     .arg4 = length,
					     .arg5 = cookie});
}

static inline struct spci_value hf_spci_mem_relinquish(uint32_t fragment_length,
						       uint32_t length,
						       uint32_t cookie)
{
	return spci_call((struct spci_value){.func = HF_SPCI_MEM_RELINQUISH,
					     .arg3 = fragment_length,
					     .arg4 = length,
					     .arg5 = cookie});
}

/**
 * Called by secondary VMs to receive a message. This will block until a message
 * is received.
 *
 * The mailbox must be cleared before a new message can be received.
 *
 * If no message is immediately available and there are no enabled and pending
 * interrupts (irrespective of whether interrupts are enabled globally), then
 * this will block until a message is available or an enabled interrupt becomes
 * pending. This matches the behaviour of the WFI instruction on AArch64, except
 * that a message becoming available is also treated like a wake-up event.
 *
 * Returns:
 *  - SPCI_MSG_SEND if a message is successfully received.
 *  - SPCI_ERROR SPCI_NOT_SUPPORTED if called from the primary VM.
 *  - SPCI_ERROR SPCI_INTERRUPTED if an interrupt happened during the call.
 */
static inline struct spci_value spci_msg_wait(void)
{
	return spci_call((struct spci_value){.func = SPCI_MSG_WAIT_32});
}

/**
 * Called by secondary VMs to receive a message. The call will return whether or
 * not a message is available.
 *
 * The mailbox must be cleared before a new message can be received.
 *
 * Returns:
 *  - SPCI_MSG_SEND if a message is successfully received.
 *  - SPCI_ERROR SPCI_NOT_SUPPORTED if called from the primary VM.
 *  - SPCI_ERROR SPCI_INTERRUPTED if an interrupt happened during the call.
 *  - SPCI_ERROR SPCI_RETRY if there was no pending message.
 */
static inline struct spci_value spci_msg_poll(void)
{
	return spci_call((struct spci_value){.func = SPCI_MSG_POLL_32});
}

/**
 * Releases the caller's mailbox so that a new message can be received. The
 * caller must have copied out all data they wish to preserve as new messages
 * will overwrite the old and will arrive asynchronously.
 *
 * Returns:
 *  - SPCI_ERROR SPCI_DENIED on failure, if the mailbox hasn't been read.
 *  - SPCI_SUCCESS on success if no further action is needed.
 *  - SPCI_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters. Waiters should be retrieved by calling
 *    hf_mailbox_waiter_get.
 */
static inline struct spci_value spci_rx_release(void)
{
	return spci_call((struct spci_value){.func = SPCI_RX_RELEASE_32});
}

/**
 * Retrieves the next VM whose mailbox became writable. For a VM to be notified
 * by this function, the caller must have called api_mailbox_send before with
 * the notify argument set to true, and this call must have failed because the
 * mailbox was not available.
 *
 * It should be called repeatedly to retrieve a list of VMs.
 *
 * Returns -1 if no VM became writable, or the id of the VM whose mailbox
 * became writable.
 */
static inline int64_t hf_mailbox_writable_get(void)
{
	return hf_call(HF_MAILBOX_WRITABLE_GET, 0, 0, 0);
}

/**
 * Retrieves the next VM waiting to be notified that the mailbox of the
 * specified VM became writable. Only primary VMs are allowed to call this.
 *
 * Returns -1 on failure or if there are no waiters; the VM id of the next
 * waiter otherwise.
 */
static inline int64_t hf_mailbox_waiter_get(spci_vm_id_t vm_id)
{
	return hf_call(HF_MAILBOX_WAITER_GET, vm_id, 0, 0);
}

/**
 * Enables or disables a given interrupt ID.
 *
 * Returns 0 on success, or -1 if the intid is invalid.
 */
static inline int64_t hf_interrupt_enable(uint32_t intid, bool enable)
{
	return hf_call(HF_INTERRUPT_ENABLE, intid, enable, 0);
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
 * Injects a virtual interrupt of the given ID into the given target vCPU.
 * This doesn't cause the vCPU to actually be run immediately; it will be taken
 * when the vCPU is next run, which is up to the scheduler.
 *
 * Returns:
 *  - -1 on failure because the target VM or vCPU doesn't exist, the interrupt
 *    ID is invalid, or the current VM is not allowed to inject interrupts to
 *    the target VM.
 *  - 0 on success if no further action is needed.
 *  - 1 if it was called by the primary VM and the primary VM now needs to wake
 *    up or kick the target vCPU.
 */
static inline int64_t hf_interrupt_inject(spci_vm_id_t target_vm_id,
					  spci_vcpu_index_t target_vcpu_idx,
					  uint32_t intid)
{
	return hf_call(HF_INTERRUPT_INJECT, target_vm_id, target_vcpu_idx,
		       intid);
}

/**
 * Sends a character to the debug log for the VM.
 *
 * Returns 0 on success, or -1 if it failed for some reason.
 */
static inline int64_t hf_debug_log(char c)
{
	return hf_call(HF_DEBUG_LOG, c, 0, 0);
}

/** Obtains the Hafnium's version of the implemented SPCI specification. */
static inline struct spci_value spci_version(void)
{
	return spci_call((struct spci_value){.func = SPCI_VERSION_32});
}

/**
 * Discovery function returning information about the implementation of optional
 * SPCI interfaces.
 *
 * Returns:
 *  - SPCI_SUCCESS in .func if the optional interface with function_id is
 * implemented.
 *  - SPCI_ERROR in .func if the optional interface with function_id is not
 * implemented.
 */
static inline struct spci_value spci_features(uint32_t function_id)
{
	return spci_call((struct spci_value){.func = SPCI_FEATURES_32,
					     .arg1 = function_id});
}

static inline struct spci_value spci_msg_send_direct_req(
	spci_vm_id_t sender_vm_id, spci_vm_id_t target_vm_id, uint32_t arg3,
	uint32_t arg4, uint32_t arg5, uint32_t arg6, uint32_t arg7)
{
	return spci_call((struct spci_value){
		.func = SPCI_MSG_SEND_DIRECT_REQ_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg3 = arg3,
		.arg4 = arg4,
		.arg5 = arg5,
		.arg6 = arg6,
		.arg7 = arg7,
	});
}

static inline struct spci_value spci_msg_send_direct_resp(
	spci_vm_id_t sender_vm_id, spci_vm_id_t target_vm_id, uint32_t arg3,
	uint32_t arg4, uint32_t arg5, uint32_t arg6, uint32_t arg7)
{
	return spci_call((struct spci_value){
		.func = SPCI_MSG_SEND_DIRECT_RESP_32,
		.arg1 = ((uint64_t)sender_vm_id << 16) | target_vm_id,
		.arg3 = arg3,
		.arg4 = arg4,
		.arg5 = arg5,
		.arg6 = arg6,
		.arg7 = arg7,
	});
}

/* SPCI_MEM_SHARE. */
/*static inline struct spci_value spci_mem_share(uintptr_t address,
					       uint32_t page_count,
					       uint32_t fragment_count,
					       uint32_t length, uint32_t handle)
{
	return spci_call((struct spci_value){.func = SPCI_MEM_SHARE_64,
					     .arg1 = address,
					     .arg2 = page_count,
					     .arg3 = fragment_count,
					     .arg4 = length,
					     .arg5 = handle});
}
*/

/* SPCI_MEM_RETRIEVE_REQ. */
static inline struct spci_value spci_mem_retrieve_req(uintptr_t address,
						      uint32_t page_count,
						      uint32_t fragment_count,
						      uint32_t length,
						      uint32_t handle)
{
	return spci_call((struct spci_value){.func = SPCI_MEM_RETRIEVE_REQ_64,
					     .arg1 = address,
					     .arg2 = page_count,
					     .arg3 = fragment_count,
					     .arg4 = length,
					     .arg5 = handle});
}

/* SPCI_MEM_RETRIEVE_RESP. */
static inline struct spci_value spci_mem_retrieve_resp(uintptr_t address,
						       uint32_t page_count,
						       uint32_t fragment_count,
						       uint32_t length,
						       uint32_t handle)
{
	return spci_call((struct spci_value){.func = SPCI_MEM_RETRIEVE_RESP_64,
					     .arg1 = 0,
					     .arg2 = 0,
					     .arg3 = fragment_count,
					     .arg4 = length,
					     .arg5 = handle});
}
/**
 * Discovery function returning information about partitions instantiated
 * in the system.
 *
 * Returns:
 *  - SPCI_SUCCESS in .func if the UUID is valid. The resultant information is
 *    passed via the RX buffer.
 *  - SPCI_ERROR in .func if the UUID could not be found.
 */
static inline struct spci_value spci_partition_info_get(uint32_t *uuid)
{
	return spci_call((struct spci_value){
		.func = SPCI_PARTITION_INFO_GET_32,
		.arg1 = uuid[0],
		.arg2 = uuid[1],
		.arg3 = uuid[2],
		.arg4 = uuid[3],
	});
}

static inline struct spci_value spci_direct_msg_resp(uint32_t src_dst, uint32_t param1, uint32_t param2, uint32_t param3, uint32_t param4, uint32_t param5)
{
	return spci_call((struct spci_value){
		.func = SPCI_MSG_SEND_DIRECT_RESP_32,
		.arg1 = src_dst,
		.arg2 = 0,
		.arg3 = param1,
		.arg4 = param2,
		.arg5 = param3,
		.arg6 = param4,
		.arg7 = param5,
	});
}

static inline struct spci_value spci_mem_op_resume(uint32_t cookie)
{
	return spci_call((struct spci_value){
		.func = SPCI_MEM_OP_RESUME,
		.arg1 = cookie,
		.arg2 = 0,
		.arg3 = 0,
		.arg4 = 0,
		.arg5 = 0,
		.arg6 = 0,
		.arg7 = 0,
	});
}
