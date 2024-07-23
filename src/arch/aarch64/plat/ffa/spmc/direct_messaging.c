/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/ffa/direct_messaging.h"

#include "hf/arch/plat/ffa.h"

#include "hf/vm.h"

bool plat_ffa_is_direct_request_valid(struct vcpu *current,
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
		 (plat_ffa_is_spmd_lp_id(sender_vm_id) ||
		  !vm_id_is_current_world(sender_vm_id))));
}

/**
 * Check that the receiver supports receipt of direct requests, and that the
 * sender supports sending direct messaging requests, in accordance to their
 * respective configurations at the partition's FF-A manifest.
 */
bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm, uint32_t func)
{
	uint16_t sender_method;
	uint16_t receiver_method;
	enum ffa_version sender_ffa_version = sender_vm->ffa_version;
	enum ffa_version receiver_ffa_version = receiver_vm->ffa_version;

	/* Check if version supports messaging function. */
	if (func == FFA_MSG_SEND_DIRECT_REQ2_64 &&
	    sender_ffa_version < FFA_VERSION_1_2) {
		dlog_verbose(
			"Sender version does not allow usage of func id "
			"0x%x.\n",
			func);
		return false;
	}

	if (func == FFA_MSG_SEND_DIRECT_REQ2_64 &&
	    receiver_ffa_version < FFA_VERSION_1_2) {
		dlog_verbose(
			"Receiver version does not allow usage of func id "
			"0x%x.\n",
			func);
		return false;
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
			"Sender can't send direct message requests via func id "
			"0x%x.\n",
			func);
		return false;
	}

	if (!vm_supports_messaging_method(receiver_vm, receiver_method)) {
		dlog_verbose(
			"Receiver can't receive direct message requests via "
			"func id 0x%x.\n",
			func);
		return false;
	}

	return true;
}

/** Check validity of a FF-A direct message response. */
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
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

bool plat_ffa_direct_request_forward(ffa_id_t receiver_vm_id,
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
