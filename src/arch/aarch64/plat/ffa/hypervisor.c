/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/other_world.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "smc.h"

static bool ffa_tee_enabled;

alignas(FFA_PAGE_SIZE) static uint8_t other_world_send_buffer[HF_MAILBOX_SIZE];
alignas(FFA_PAGE_SIZE) static uint8_t other_world_recv_buffer[HF_MAILBOX_SIZE];

/** Returns information on features specific to the NWd. */
struct ffa_value plat_ffa_features(uint32_t function_id)
{
	switch (function_id) {
	case FFA_MSG_POLL_32:
	case FFA_YIELD_32:
	case FFA_MSG_SEND_32:
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	default:
		return ffa_error(FFA_NOT_SUPPORTED);
	}
}

struct ffa_value plat_ffa_spmc_id_get(void)
{
	if (ffa_tee_enabled) {
		/* Fetch the SPMC ID from the SPMD using FFA_SPM_ID_GET. */
		return smc_ffa_call(
			(struct ffa_value){.func = FFA_SPM_ID_GET_32});
	}

	return (struct ffa_value){.func = FFA_ERROR_32,
				  .arg2 = FFA_NOT_SUPPORTED};
}

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (Hypervisor)\n");
}

void plat_ffa_init(bool tee_enabled)
{
	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct ffa_value ret;
	uint32_t func;

	if (!tee_enabled) {
		return;
	}

	CHECK(other_world_vm != NULL);

	arch_ffa_init();

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

	ffa_tee_enabled = true;

	dlog_verbose("TEE finished setting up buffers.\n");
}

bool plat_ffa_run_forward(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	/*
	 * VM's requests should be forwarded to the SPMC, if target is an SP.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		*ret = arch_other_world_call((struct ffa_value){
			.func = FFA_RUN_32, ffa_vm_vcpu(vm_id, vcpu_idx)});
		return true;
	}

	return false;
}

/**
 * Check validity of a FF-A direct message request.
 */
bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_vm_id_t sender_vm_id,
				      ffa_vm_id_t receiver_vm_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/*
	 * The primary VM can send direct message request to
	 * any other VM (but itself) or SP, but can't spoof
	 * a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       current_vm_id == HF_PRIMARY_VM_ID;
}

/**
 * Check validity of a FF-A notifications bitmap create.
 */
bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id)
{
	/*
	 * Call should only be used by the Hypervisor, so any attempt of
	 * invocation from NWd FF-A endpoints should fail.
	 */
	(void)current;
	(void)vm_id;

	return false;
}

/**
 * Check validity of a FF-A direct message response.
 */
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/*
	 * Secondary VMs can send direct message responses to
	 * the PVM, but can't spoof a different sender.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       receiver_vm_id == HF_PRIMARY_VM_ID;
}

bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret)
{
	if (!ffa_tee_enabled) {
		return false;
	}

	/*
	 * VM's requests should be forwarded to the SPMC, if receiver is an SP.
	 */
	dlog_verbose("%s calling SPMC %#x %#x %#x %#x %#x\n", __func__,
		     args.func, args.arg1, args.arg2, args.arg3, args.arg4);
	if (!vm_id_is_current_world(receiver_vm_id)) {
		*ret = arch_other_world_call(args);
		return true;
	}

	return false;
}

ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index)
{
	return index | FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
}

bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle)
{
	return (handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	       FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t vm_id, const struct vm *target)
{
	ffa_partition_properties_t result = target->messaging_method;
	/*
	 * VMs support indirect messaging only in the Normal World.
	 * Primary VM cannot receive direct requests.
	 * Secondary VMs cannot send direct requests.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		result &= ~FFA_PARTITION_INDIRECT_MSG;
	}
	if (target->id == HF_PRIMARY_VM_ID) {
		result &= ~FFA_PARTITION_DIRECT_REQ_RECV;
	} else {
		result &= ~FFA_PARTITION_DIRECT_REQ_SEND;
	}
	return result;
}

bool plat_ffa_vm_managed_exit_supported(struct vm *vm)
{
	(void)vm;

	return false;
}

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;
	/** If Hafnium is hypervisor, receiver needs to be current vm. */
	return sender_id != receiver_id && current_vm_id == receiver_id;
}

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/* If Hafnium is hypervisor, sender needs to be current vm. */
	return sender_id == current_vm_id && sender_id != receiver_id;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/* If Hafnium is hypervisor, receiver needs to be current vm. */
	return (current_vm_id == receiver_id);
}

struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	/* TODO: Forward call to the SPMC */
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id)
{
	/* TODO: Forward call to the SPMC */
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id)
{
	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	return (struct vm_locked){.vm = NULL};
}

bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id)
{
	return vm_id_is_current_world(vm_id);
}
