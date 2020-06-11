/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/other_world.h"

#include "hf/arch/mmu.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/panic.h"
#include "hf/vm.h"

#include "smc.h"

#if SECURE_WORLD == 0

alignas(PAGE_SIZE) static uint8_t other_world_send_buffer[HF_MAILBOX_SIZE];
alignas(PAGE_SIZE) static uint8_t other_world_recv_buffer[HF_MAILBOX_SIZE];

#endif

void arch_other_world_init(void)
{
#if SECURE_WORLD == 0

	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct ffa_value ret;
	uint32_t func;

	CHECK(other_world_vm != NULL);

	/* Setup TEE VM RX/TX buffers */
	other_world_vm->mailbox.send = &other_world_send_buffer;
	other_world_vm->mailbox.recv = &other_world_recv_buffer;

	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RXTX_MAP_64,
		.arg1 = pa_addr(
			pa_from_va(va_from_ptr(other_world_vm->mailbox.recv))),
		.arg2 = pa_addr(
			pa_from_va(va_from_ptr(other_world_vm->mailbox.send))),
		.arg3 = HF_MAILBOX_SIZE / FFA_PAGE_SIZE});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == SMCCC_ERROR_UNKNOWN) {
		dlog_error(
			"Unknown function setting up TEE message buffers. "
			"Memory sharing with TEE will not work.\n");
		return;
	}
	if (func == FFA_ERROR_32) {
		panic("Error %d setting up TEE message buffers.", ret.arg2);
	} else if (func != FFA_SUCCESS_32) {
		panic("Unexpected function %#x returned setting up TEE message "
		      "buffers.",
		      ret.func);
	}
	dlog_verbose("TEE finished setting up buffers.\n");
#endif
}

bool arch_other_world_vm_init(struct vm *other_world_vm, struct mpool *ppool)
{
#if SECURE_WORLD == 0

	(void)other_world_vm;
	(void)ppool;

	return true;

#else

	struct vm_locked other_world_vm_locked;
	bool ret = false;

	/* Map 1TB address range to "Other world VM" Stage-2 */
	other_world_vm_locked = vm_lock(other_world_vm);

	if (!vm_identity_map(other_world_vm_locked, pa_init(0),
			     pa_init(UINT64_C(1024) * 1024 * 1024 * 1024),
			     MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS,
			     ppool, NULL)) {
		dlog_error(
			"Unable to initialise address space for "
			"Hypervisor VM.\n");
		goto out;
	}

	ret = true;

out:
	vm_unlock(&other_world_vm_locked);

	return ret;

#endif
}

/**
 * Check validity of a FF-A direct message request.
 */
bool arch_other_world_is_direct_request_valid(struct vcpu *current,
					      ffa_vm_id_t sender_vm_id,
					      ffa_vm_id_t receiver_vm_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

#if SECURE_WORLD == 1

	/*
	 * The normal world can send direct message requests
	 * via the Hypervisor to any SP.
	 */
	return sender_vm_id != receiver_vm_id &&
	       current_vm_id == HF_HYPERVISOR_VM_ID &&
	       vm_id_is_current_world(receiver_vm_id) &&
	       !vm_id_is_current_world(sender_vm_id);

#else

	/*
	 * The primary VM can send direct message request to
	 * any other VM (but itself) or SP, but can't spoof
	 * a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       current_vm_id == HF_PRIMARY_VM_ID;

#endif

	return false;
}

/**
 * Check validity of a FF-A direct message response.
 */
bool arch_other_world_is_direct_response_valid(struct vcpu *current,
					       ffa_vm_id_t sender_vm_id,
					       ffa_vm_id_t receiver_vm_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

#if SECURE_WORLD == 1

	/*
	 * Direct message responses emitted from a SP
	 * target a VM in NWd.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       vm_id_is_current_world(sender_vm_id) &&
	       !vm_id_is_current_world(receiver_vm_id);

#else

	/*
	 * Secondary VMs can send direct message responses to
	 * the PVM, but can't spoof a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       receiver_vm_id == HF_PRIMARY_VM_ID;

#endif

	return false;
}

struct ffa_value arch_other_world_call(struct ffa_value args)
{
	return smc_ffa_call(args);
}
