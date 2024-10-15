/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/ffa/indirect_messaging.h"

#include "hf/vm.h"

/**
 * Check that sender and receiver support indirect messages, in accordance
 * to their configurations in the respective partition's FF-A manifest.
 * Note: check is done at virtual FF-A instance only.
 */
bool plat_ffa_is_indirect_msg_supported(struct vm_locked sender_locked,
					struct vm_locked receiver_locked)
{
	struct vm *sender_vm = sender_locked.vm;
	struct vm *receiver_vm = receiver_locked.vm;

	/*
	 * SPMC doesn't have information about VMs' configuration hence can't
	 * check if they are allowed to send indirect messages, but it's not a
	 * security threat.
	 */
	if (sender_vm->ffa_version < FFA_VERSION_1_1) {
		dlog_verbose(
			"Sender %x FF-A version (%x) doesn't support Indirect "
			"Message. FF-A v1.1 is needed.\n",
			sender_vm->id, sender_vm->ffa_version);
		return false;
	}

	if (receiver_vm->ffa_version < FFA_VERSION_1_1) {
		dlog_verbose(
			"Receiver %x FF-A version (%x) doesn't support "
			"Indirect Message. FF-A v1.1 is needed.\n",
			receiver_vm->id, receiver_vm->ffa_version);
		return false;
	}

	if (vm_id_is_current_world(sender_vm->id)) {
		if (!vm_supports_messaging_method(sender_vm,
						  FFA_PARTITION_INDIRECT_MSG)) {
			dlog_verbose("VM %#x can't send indirect messages.\n",
				     sender_vm->id);
			return false;
		}
	}

	if (vm_id_is_current_world(receiver_vm->id)) {
		if (!vm_supports_messaging_method(receiver_vm,
						  FFA_PARTITION_INDIRECT_MSG)) {
			dlog_verbose(
				"VM %#x can't receive indirect messages.\n",
				receiver_vm->id);
			return false;
		}
	}

	return true;
}
bool plat_ffa_msg_send2_forward(ffa_id_t receiver_vm_id, ffa_id_t sender_vm_id,
				struct ffa_value *ret)
{
	/* SPMC never needs to forward a FFA_MSG_SEND2, it always handles it. */
	(void)receiver_vm_id;
	(void)sender_vm_id;
	(void)ret;
	return false;
}
