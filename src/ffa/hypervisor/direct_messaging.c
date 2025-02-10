/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/direct_messaging.h"

#include "hf/arch/other_world.h"

#include "hf/ffa/init.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

/**
 * Check validity of a FF-A direct message request.
 */
bool ffa_direct_msg_is_direct_request_valid(struct vcpu *current,
					    ffa_id_t sender_vm_id,
					    ffa_id_t receiver_vm_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	/*
	 * The primary VM can send direct message request to
	 * any other VM (but itself) or SP, but can't spoof
	 * a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id && vm_is_primary(current->vm);
}

bool ffa_direct_msg_is_direct_request_supported(struct vm *sender_vm,
						struct vm *receiver_vm,
						uint32_t func)
{
	(void)sender_vm;
	(void)receiver_vm;
	(void)func;

	/*
	 * As Hypervisor is only meant to be used as a test artifact, allow
	 * direct messaging for all VMs.
	 */
	return true;
}

/**
 * Check validity of a FF-A direct message response.
 */
bool ffa_direct_msg_is_direct_response_valid(struct vcpu *current,
					     ffa_id_t sender_vm_id,
					     ffa_id_t receiver_vm_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	/*
	 * Secondary VMs can send direct message responses to
	 * the PVM, but can't spoof a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       receiver_vm_id == HF_PRIMARY_VM_ID;
}

bool ffa_direct_msg_direct_request_forward(ffa_id_t receiver_vm_id,
					   struct ffa_value args,
					   struct ffa_value *ret)
{
	if (!ffa_init_is_tee_enabled()) {
		dlog_verbose("Not forwarding: ffa_tee_enabled is false\n");
		return false;
	}

	/*
	 * VM's requests should be forwarded to the SPMC, if receiver is an SP.
	 */
	if (vm_id_is_current_world(receiver_vm_id)) {
		dlog_verbose(
			"Not forwarding: receiver VM %#x is in the same "
			"world\n",
			receiver_vm_id);
		return false;
	}

	switch (args.func) {
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ_64:
		*ret = arch_other_world_call(args);
		break;
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		*ret = arch_other_world_call_ext(args);
		break;
	default:
		panic("Invalid direct message function %#x\n", args.func);
		break;
	}

	return true;
}

void ffa_direct_msg_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)receiver_vcpu_locked;
	(void)sender_vm_id;
}

void ffa_direct_msg_unwind_call_chain_ffa_direct_resp(
	struct vcpu_locked current_locked, struct vcpu_locked next_locked)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)next_locked;
}

bool ffa_direct_msg_handle_framework_msg(struct ffa_value args,
					 struct ffa_value *ret,
					 struct vcpu *current,
					 struct vcpu **next)
{
	(void)args;
	(void)ret;
	(void)current;
	(void)next;

	return false;
}

bool ffa_direct_msg_is_spmd_lp_id(ffa_id_t vm_id)
{
	(void)vm_id;
	return false;
}
