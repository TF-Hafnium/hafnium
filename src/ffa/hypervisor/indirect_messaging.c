/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/indirect_messaging.h"

#include "hf/arch/other_world.h"

#include "hf/api.h"
#include "hf/ffa/init.h"
#include "hf/ffa_internal.h"
#include "hf/vm.h"

bool ffa_indirect_msg_is_supported(struct vm_locked sender_locked,
				   struct vm_locked receiver_locked)
{
	(void)sender_locked;
	(void)receiver_locked;

	/*
	 * Hypervisor is only for testing purposes, always allow indirect
	 * messages from VM.
	 */
	return true;
}

bool ffa_indirect_msg_send2_forward(ffa_id_t receiver_vm_id,
				    ffa_id_t sender_vm_id,
				    struct ffa_value *ret)
{
	/* FFA_MSG_SEND2 is forwarded to SPMC when the receiver is an SP. */
	if (vm_id_is_current_world(receiver_vm_id)) {
		return false;
	}

	/*
	 * Set the sender in arg1 to allow the SPMC to retrieve
	 * VM's TX buffer to copy in SP's RX buffer.
	 */
	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_MSG_SEND2_32,
		.arg1 = sender_vm_id << 16,
	});

	if (ffa_func_id(*ret) != FFA_SUCCESS_32) {
		dlog_verbose(
			"Failed forwarding FFA_MSG_SEND2_32 to the "
			"SPMC, got error %s (%d).\n",
			ffa_error_name(ffa_error_code(*ret)),
			ffa_error_code(*ret));
	}

	return true;
}

/**
 * Checks whether the vCPU's attempt to wait for a message has already been
 * interrupted or whether it is allowed to block.
 */
static bool ffa_indirect_msg_recv_block_interrupted(
	struct vcpu_locked current_locked)
{
	bool interrupted;

	/*
	 * Don't block if there are enabled and pending interrupts, to match
	 * behaviour of wait_for_interrupt.
	 */
	interrupted = (vcpu_virt_interrupt_count_get(current_locked) > 0);

	return interrupted;
}

/**
 * Returns true if there is something in the return code, either a v1.0
 * FFA_MSG_SEND, or an FFA_ERROR.
 */
static bool ffa_indirect_msg_return_pending_messages(struct vm_locked vm_locked,
						     struct ffa_value *ret)
{
	/* Return pending messages without blocking. */
	if (vm_locked.vm->mailbox.state == MAILBOX_STATE_FULL) {
		*ret = ffa_msg_recv_return(vm_locked.vm);
		if (ret->func == FFA_MSG_SEND_32) {
			vm_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;
		}
		return true;
	}

	return false;
}

/**
 * Receives a message from the mailbox. If one isn't available, this function
 * can optionally block the caller until one becomes available.
 *
 * No new messages can be received until the mailbox has been cleared.
 */
struct ffa_value ffa_indirect_msg_recv(bool block,
				       struct vcpu_locked current_locked,
				       struct vcpu **next)
{
	struct vm *vm = current_locked.vcpu->vm;
	struct vcpu *current = current_locked.vcpu;
	struct vm_locked vm_locked;
	struct ffa_value return_code;

	/*
	 * The primary VM will receive messages as a status code from running
	 * vCPUs and must not call this function.
	 */
	if (vm_is_primary(vm)) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	/*
	 * Deny if vCPU is executing in context of an FFA_MSG_SEND_DIRECT_REQ
	 * invocation.
	 */
	if (is_ffa_direct_msg_request_ongoing(current_locked)) {
		return ffa_error(FFA_DENIED);
	}

	vcpu_unlock(&current_locked);
	vm_locked = vm_lock(vm);
	current_locked = vcpu_lock(current);

	if (ffa_indirect_msg_return_pending_messages(vm_locked, &return_code)) {
		goto out;
	}

	/* No pending message so fail if not allowed to block. */
	if (!block) {
		return_code = ffa_error(FFA_RETRY);
		goto out;
	}

	/*
	 * From this point onward this call can only be interrupted or a message
	 * received. If a message is received the return value will be set at
	 * that time to FFA_SUCCESS.
	 */
	return_code = ffa_error(FFA_INTERRUPTED);
	if (ffa_indirect_msg_recv_block_interrupted(current_locked)) {
		goto out;
	}

	{
		/* Switch back to primary VM to block. */
		struct ffa_value run_return = {
			.func = FFA_MSG_WAIT_32,
			.arg1 = ffa_vm_vcpu(vm->id,
					    vcpu_index(current_locked.vcpu)),
		};

		*next = api_switch_to_primary(current_locked, run_return,
					      VCPU_STATE_WAITING);
	}
out:
	vm_unlock(&vm_locked);

	return return_code;
}

/**
 * Notifies the `to` VM about the message currently in its mailbox, possibly
 * with the help of the primary VM.
 */
static struct ffa_value deliver_msg(struct vm_locked to, ffa_id_t from_id,
				    struct vcpu_locked current_locked,
				    struct vcpu **next)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct ffa_value primary_ret = {
		.func = FFA_MSG_SEND_32,
		.arg1 = ((uint32_t)from_id << 16) | to.vm->id,
	};

	/* Messages for the primary VM are delivered directly. */
	if (vm_is_primary(to.vm)) {
		/*
		 * Only tell the primary VM the size and other details if the
		 * message is for it, to avoid leaking data about messages for
		 * other VMs.
		 */
		primary_ret = ffa_msg_recv_return(to.vm);

		*next = api_switch_to_primary(current_locked, primary_ret,
					      VCPU_STATE_BLOCKED);
		return ret;
	}

	to.vm->mailbox.state = MAILBOX_STATE_FULL;

	/* Messages for the TEE are sent on via the dispatcher. */
	if (to.vm->id == HF_TEE_VM_ID) {
		struct ffa_value call = ffa_msg_recv_return(to.vm);

		ret = arch_other_world_call(call);
		/*
		 * After the call to the TEE completes it must have finished
		 * reading its RX buffer, so it is ready for another message.
		 */
		to.vm->mailbox.state = MAILBOX_STATE_EMPTY;
		/*
		 * Don't return to the primary VM in this case, as the TEE is
		 * not (yet) scheduled via FF-A.
		 */
		return ret;
	}

	/* Return to the primary VM directly or with a switch. */
	if (from_id != HF_PRIMARY_VM_ID) {
		*next = api_switch_to_primary(current_locked, primary_ret,
					      VCPU_STATE_BLOCKED);
	}

	return ret;
}

/*
 * Copies data from the sender's send buffer to the recipient's receive buffer
 * and notifies the recipient.
 *
 * If the recipient's receive buffer is busy, it can optionally register the
 * caller to be notified when the recipient's receive buffer becomes available.
 */
struct ffa_value ffa_indirect_msg_send(ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id, uint32_t size,
				       struct vcpu *current, struct vcpu **next)
{
	struct vm *from = current->vm;
	struct vm *to;
	struct vm_locked to_locked;
	const void *from_msg;
	struct ffa_value ret;
	struct vcpu_locked current_locked;
	bool is_direct_request_ongoing;

	/* Ensure sender VM ID corresponds to the current VM. */
	if (sender_vm_id != from->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Disallow reflexive requests as this suggests an error in the VM. */
	if (receiver_vm_id == from->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Limit the size of transfer. */
	if (size > FFA_MSG_PAYLOAD_MAX) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Ensure the receiver VM exists. */
	to = vm_find(receiver_vm_id);
	if (to == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Deny if vCPU is executing in context of an FFA_MSG_SEND_DIRECT_REQ
	 * invocation.
	 */
	current_locked = vcpu_lock(current);
	is_direct_request_ongoing =
		is_ffa_direct_msg_request_ongoing(current_locked);

	if (is_direct_request_ongoing) {
		ret = ffa_error(FFA_DENIED);
		goto out_current;
	}

	/*
	 * Check that the sender has configured its send buffer. If the tx
	 * mailbox at from_msg is configured (i.e. from_msg != NULL) then it can
	 * be safely accessed after releasing the lock since the tx mailbox
	 * address can only be configured once.
	 * A VM's lock must be acquired before any of its vCPU's lock. Hence,
	 * unlock current vCPU and acquire it immediately after its VM's lock.
	 */
	vcpu_unlock(&current_locked);
	sl_lock(&from->lock);
	current_locked = vcpu_lock(current);
	from_msg = from->mailbox.send;
	sl_unlock(&from->lock);

	if (from_msg == NULL) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_current;
	}

	to_locked = vm_lock(to);

	if (vm_is_mailbox_busy(to_locked)) {
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	/* Copy data. */
	memcpy_s(to->mailbox.recv, FFA_MSG_PAYLOAD_MAX, from_msg, size);
	to->mailbox.recv_size = size;
	to->mailbox.recv_sender = sender_vm_id;
	to->mailbox.recv_func = FFA_MSG_SEND_32;
	to->mailbox.state = MAILBOX_STATE_FULL;
	ret = deliver_msg(to_locked, sender_vm_id, current_locked, next);

out:
	vm_unlock(&to_locked);

out_current:
	vcpu_unlock(&current_locked);

	return ret;
}
