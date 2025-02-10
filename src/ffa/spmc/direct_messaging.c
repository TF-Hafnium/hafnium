/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/direct_messaging.h"

#include "hf/arch/gicv3.h"
#include "hf/arch/host_timer.h"

#include "hf/api.h"
#include "hf/bits.h"
#include "hf/ffa/interrupts.h"
#include "hf/ffa_internal.h"
#include "hf/plat/interrupts.h"

#include "psci.h"

bool ffa_direct_msg_is_direct_request_valid(struct vcpu *current,
					    ffa_id_t sender_vm_id,
					    ffa_id_t receiver_vm_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	/*
	 * The normal world can send direct message requests
	 * via the Hypervisor to any SP. Currently SPs can only send
	 * direct messages to each other and not to the NWd.
	 * SPMD Logical partitions can also send direct messages.
	 */
	return sender_vm_id != receiver_vm_id &&
	       vm_id_is_current_world(receiver_vm_id) &&
	       (sender_vm_id == current_vm_id ||
		(current_vm_id == HF_HYPERVISOR_VM_ID &&
		 (ffa_direct_msg_is_spmd_lp_id(sender_vm_id) ||
		  !vm_id_is_current_world(sender_vm_id))));
}

/**
 * Check that the receiver supports receipt of direct requests, and that the
 * sender supports sending direct messaging requests, in accordance to their
 * respective configurations at the partition's FF-A manifest.
 */
bool ffa_direct_msg_is_direct_request_supported(struct vm *sender_vm,
						struct vm *receiver_vm,
						uint32_t func)
{
	uint16_t sender_method;
	uint16_t receiver_method;
	enum ffa_version sender_ffa_version = sender_vm->ffa_version;
	enum ffa_version receiver_ffa_version = receiver_vm->ffa_version;

	/* Check if version supports messaging function. */
	if (func == FFA_MSG_SEND_DIRECT_REQ2_64) {
		if (sender_ffa_version < FFA_VERSION_1_2) {
			dlog_verbose(
				"Sender version does not allow usage of %s\n",
				ffa_func_name(func));
			return false;
		}

		if (receiver_ffa_version < FFA_VERSION_1_2) {
			dlog_verbose(
				"Receiver version does not allow usage of "
				"%s\n",
				ffa_func_name(func));
			return false;
		}
	}

	/*
	 * Check if endpoint is configured to accept direct requests via given
	 * method.
	 */
	sender_method = (func == FFA_MSG_SEND_DIRECT_REQ2_64)
				? FFA_PARTITION_DIRECT_REQ2_SEND
				: FFA_PARTITION_DIRECT_REQ_SEND;
	receiver_method = (func == FFA_MSG_SEND_DIRECT_REQ2_64)
				  ? FFA_PARTITION_DIRECT_REQ2_RECV
				  : FFA_PARTITION_DIRECT_REQ_RECV;

	if (!vm_supports_messaging_method(sender_vm, sender_method)) {
		dlog_verbose(
			"Sender can't sender direct message requests via %s\n",
			ffa_func_name(func));
		return false;
	}

	if (!vm_supports_messaging_method(receiver_vm, receiver_method)) {
		dlog_verbose(
			"Receiver can't receive direct message requests via "
			"%s\n",
			ffa_func_name(func));
		return false;
	}

	return true;
}

/** Check validity of a FF-A direct message response. */
bool ffa_direct_msg_is_direct_response_valid(struct vcpu *current,
					     ffa_id_t sender_vm_id,
					     ffa_id_t receiver_vm_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	/*
	 * Direct message responses emitted from a SP target either the NWd,
	 * or EL3 SPMD logical partition or another SP.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       vm_id_is_current_world(sender_vm_id);
}

bool ffa_direct_msg_direct_request_forward(ffa_id_t receiver_vm_id,
					   struct ffa_value args,
					   struct ffa_value *ret)
{
	/*
	 * SPs are not supposed to issue requests to VMs.
	 */
	(void)receiver_vm_id;
	(void)args;
	(void)ret;

	return false;
}

/*
 * Unwind the present call chain upon the invocation of
 * FFA_MSG_SEND_DIRECT_RESP ABI. The function also returns
 * the partition ID to which the caller must return to. In
 * case the call chain was started by an SPMD logical
 * partition direct message, at the end of the call chain,
 * we need to return other world's id so that the SPMC can
 * return to the SPMD.
 */
void ffa_direct_msg_unwind_call_chain_ffa_direct_resp(
	struct vcpu_locked current_locked, struct vcpu_locked next_locked)
{
	struct vcpu *next = next_locked.vcpu;
	ffa_id_t receiver_vm_id = next->vm->id;
	struct vcpu *current = current_locked.vcpu;

	assert(current->call_chain.next_node == NULL);
	current->scheduling_mode = NONE;
	current->rt_model = RTM_NONE;

	/* Allow interrupts if they were masked earlier. */
	ffa_interrupts_unmask(current);

	if (!vm_id_is_current_world(receiver_vm_id)) {
		/* End of NWd scheduled call chain. */
		assert(current->call_chain.prev_node == NULL);
	} else {
		/* Removing a node from an existing call chain. */
		vcpu_call_chain_remove_node(current_locked, next_locked);
	}
}

/*
 * Start winding the call chain or continue to wind the present one upon the
 * invocation of FFA_MSG_SEND_DIRECT_REQ or FFA_MSG_SEND_DIRECT_REQ2 (FF-A v1.2)
 * ABI.
 */
void ffa_direct_msg_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id)
{
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *receiver_vcpu = receiver_vcpu_locked.vcpu;

	CHECK(receiver_vcpu->scheduling_mode == NONE);
	CHECK(receiver_vcpu->call_chain.prev_node == NULL);
	CHECK(receiver_vcpu->call_chain.next_node == NULL);
	CHECK(receiver_vcpu->rt_model == RTM_NONE);

	receiver_vcpu->rt_model = RTM_FFA_DIR_REQ;

	if (!vm_id_is_current_world(sender_vm_id)) {
		/* Start of NWd scheduled call chain. */
		receiver_vcpu->scheduling_mode = NWD_MODE;
	} else if (ffa_direct_msg_is_spmd_lp_id(sender_vm_id)) {
		receiver_vcpu->scheduling_mode = SPMC_MODE;
	} else {
		/* Adding a new node to an existing call chain. */
		vcpu_call_chain_extend(current_locked, receiver_vcpu_locked);
		receiver_vcpu->scheduling_mode = current->scheduling_mode;
	}
	ffa_interrupts_mask(receiver_vcpu_locked);
}

bool ffa_direct_msg_precedes_in_call_chain(struct vcpu_locked current_locked,
					   struct vcpu_locked target_locked)
{
	struct vcpu *prev_node;
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *target = target_locked.vcpu;

	assert(current != NULL);
	assert(target != NULL);

	prev_node = current->call_chain.prev_node;

	while (prev_node != NULL) {
		if (prev_node == target) {
			return true;
		}

		/* The target vCPU is not it's immediate predecessor. */
		prev_node = prev_node->call_chain.prev_node;
	}

	/* Search terminated. Reached start of call chain. */
	return false;
}

/**
 * Check that the arguments to a VM availability message are correct.
 * Returns `FFA_SUCCESS_32` if the arguments are correct.
 * Returns `FFA_INVALID_PARAMETERS` if:
 * - the receiver is not a valid VM
 * - the receiver has not subscribed to the message type
 */
static struct ffa_value check_vm_availability_message(struct ffa_value args)
{
	struct ffa_value ret = ffa_error(FFA_INVALID_PARAMETERS);
	enum ffa_framework_msg_func func = ffa_framework_msg_func(args);
	ffa_id_t receiver_id = ffa_receiver(args);
	struct vm_locked receiver = vm_find_locked(receiver_id);

	if (receiver.vm == NULL) {
		dlog_verbose(
			"VM availability messaging: could not find SP %#x\n",
			receiver_id);
		return ret;
	}

	/* only valid if receiver has subscribed */
	if (func == FFA_FRAMEWORK_MSG_VM_CREATION_REQ &&
	    !receiver.vm->vm_availability_messages.vm_created) {
		dlog_verbose(
			"VM availability messaging: SP %#x is not subscribed "
			"to VM creation messages\n",
			receiver_id);
		goto out;
	}

	if (func == FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ &&
	    !receiver.vm->vm_availability_messages.vm_destroyed) {
		dlog_verbose(
			"VM availability messaging: SP %#x is not subscribed "
			"to VM destruction messages\n",
			receiver_id);
		goto out;
	}

	if (ANY_BITS_SET(args.arg5, FFA_VM_AVAILABILITY_MESSAGE_SBZ_HI,
			 FFA_VM_AVAILABILITY_MESSAGE_SBZ_LO)) {
		dlog_warning(
			"VM availability messaging: bits[%u:%u] of w5 are "
			"reserved and should be zero (w5=%#lx)\n",
			FFA_VM_AVAILABILITY_MESSAGE_SBZ_HI,
			FFA_VM_AVAILABILITY_MESSAGE_SBZ_LO, args.arg5);
	}

	if (args.arg6 != 0) {
		dlog_warning(
			"VM availability messaging: w6 is reserved and should "
			"be zero (w6=%#lx)\n",
			args.arg6);
	}

	if (args.arg7 != 0) {
		dlog_warning(
			"VM availability messaging: w7 is reserved and should "
			"be zero (w7=%#lx)\n",
			args.arg7);
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:

	vm_unlock(&receiver);
	return ret;
}

void spmc_exit_to_nwd(struct vcpu *owd_vcpu)
{
	struct vcpu *deadline_vcpu =
		timer_find_vcpu_nearest_deadline(owd_vcpu->cpu);

	/*
	 * SPMC tracks a vCPU's timer deadline through its host timer such that
	 * it can bring back execution from normal world to signal the timer
	 * virtual interrupt to the SP's vCPU.
	 */
	if (deadline_vcpu != NULL) {
		host_timer_track_deadline(&deadline_vcpu->regs.arch_timer);
	}
}

/*
 * TODO: the power management event reached the SPMC. In a later iteration, the
 * power management event can be passed to the SP by resuming it.
 */
static struct ffa_value handle_psci_framework_msg(struct ffa_value args,
						  struct vcpu *current,
						  struct vcpu **next)
{
	(void)next;
	enum psci_return_code psci_msg_response;
	uint64_t psci_func = args.arg3;

	switch (psci_func) {
	case PSCI_CPU_OFF: {
		/*
		 * Mark all the vCPUs pinned on this CPU as OFF. Note that the
		 * vCPU of an UP SP is not turned off since SPMC can migrate it
		 * to an online CPU when needed.
		 */
		for (ffa_vm_count_t index = 0; index < vm_get_count();
		     ++index) {
			struct vm *vm = vm_find_index(index);

			if (vm->vcpu_count > 1) {
				struct vcpu *vcpu;
				struct vcpu_locked vcpu_locked;

				vcpu = vm_get_vcpu(vm, cpu_index(current->cpu));
				vcpu_locked = vcpu_lock(vcpu);
				vcpu->state = VCPU_STATE_OFF;
				vcpu_unlock(&vcpu_locked);
				dlog_verbose("SP%u turned OFF on CPU%zu\n",
					     vm->id, cpu_index(current->cpu));
			}
		}

		/*
		 * Mark the CPU as turned off and reset the field tracking if
		 * all the pinned vCPUs have been booted on this CPU.
		 */
		cpu_off(current->cpu);
		current->cpu->last_sp_initialized = false;
		psci_msg_response = PSCI_RETURN_SUCCESS;

		break;
	}
	default:
		dlog_error(
			"FF-A PSCI framework message not handled "
			"%#lx %#lx %#lx %#lx\n",
			args.func, args.arg1, args.arg2, args.arg3);
		psci_msg_response = PSCI_ERROR_NOT_SUPPORTED;
	}

	return ffa_framework_msg_resp(HF_SPMC_VM_ID, HF_SPMD_VM_ID,
				      FFA_FRAMEWORK_MSG_PSCI_RESP,
				      psci_msg_response);
}

/**
 * Handle special direct messages from SPMD to SPMC.
 */
static void handle_spmd_to_spmc_framework_msg(struct ffa_value args,
					      struct vcpu *current,
					      struct ffa_value *ret,
					      struct vcpu **next)
{
	ffa_id_t sender = ffa_sender(args);
	ffa_id_t receiver = ffa_receiver(args);
	ffa_id_t current_vm_id = current->vm->id;
	enum ffa_framework_msg_func func = ffa_framework_msg_func(args);

	assert(ffa_is_framework_msg(args));

	/*
	 * Check if direct message request is originating from the SPMD,
	 * directed to the SPMC and the message is a framework message.
	 */
	if (!(sender == HF_SPMD_VM_ID && receiver == HF_SPMC_VM_ID &&
	      current_vm_id == HF_OTHER_WORLD_ID)) {
		dlog_verbose(
			"Power Management message: Invalid Sender ID: %#x or "
			"Receiver ID: %#x\n",
			sender, receiver);
		*ret = ffa_error(FFA_INVALID_PARAMETERS);
		return;
	}

	/*
	 * The framework message is conveyed by EL3/SPMD to SPMC so the
	 * current VM id must match to the other world VM id.
	 */
	CHECK(current->vm->id == HF_HYPERVISOR_VM_ID);

	switch (func) {
	case FFA_FRAMEWORK_MSG_PSCI_REQ: {
		*ret = handle_psci_framework_msg(args, current, next);
		return;
	}
	case SPMD_FRAMEWORK_MSG_FFA_VERSION_REQ: {
		struct ffa_value version_ret =
			api_ffa_version(current, args.arg3);
		*ret = ffa_framework_msg_resp(
			HF_SPMC_VM_ID, HF_SPMD_VM_ID,
			SPMD_FRAMEWORK_MSG_FFA_VERSION_RESP, version_ret.func);
		return;
	}
	default:
		dlog_error("FF-A framework message not handled %#lx\n",
			   args.arg2);

		/*
		 * TODO: the framework message that was conveyed by a direct
		 * request is not handled although we still want to complete
		 * by a direct response. However, there is no defined error
		 * response to state that the message couldn't be handled.
		 * An alternative would be to return FFA_ERROR.
		 */
		*ret = ffa_framework_msg_resp(HF_SPMC_VM_ID, HF_SPMD_VM_ID,
					      func, 0);
		return;
	}
}

/**
 * Handle framework messages related to VM availability, PSCI power management,
 * and FF-A version discovery.
 * Returns true if the framework message is handled.
 * Else false if further handling is required.
 */
bool ffa_direct_msg_handle_framework_msg(struct ffa_value args,
					 struct ffa_value *ret,
					 struct vcpu *current,
					 struct vcpu **next)
{
	enum ffa_framework_msg_func func = ffa_framework_msg_func(args);

	switch (func) {
	case FFA_FRAMEWORK_MSG_VM_CREATION_REQ:
	case FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ:
		*ret = check_vm_availability_message(args);
		if (ret->func != FFA_SUCCESS_32) {
			return true;
		}
		break;
	case FFA_FRAMEWORK_MSG_PSCI_REQ:
	case SPMD_FRAMEWORK_MSG_FFA_VERSION_REQ:
		handle_spmd_to_spmc_framework_msg(args, current, ret, next);
		return true;
	default:
		dlog_verbose(
			"Unknown function ID specified with framework "
			"message\n");
		*ret = ffa_error(FFA_INVALID_PARAMETERS);
		return true;
	}

	return false;
}

bool ffa_direct_msg_is_spmd_lp_id(ffa_id_t vm_id)
{
	return (vm_id >= EL3_SPMD_LP_ID_START && vm_id <= EL3_SPMD_LP_ID_END);
}
