/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"
#include "hf/arch/ffa.h"
#include "hf/arch/other_world.h"
#include "hf/arch/plat/ffa.h"

#include "hf/api.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/ffa_memory.h"
#include "hf/ffa_memory_internal.h"
#include "hf/std.h"
#include "hf/vcpu.h"
#include "hf/vm.h"
#include "hf/vm_ids.h"

#include "msr.h"
#include "smc.h"
#include "sysregs.h"

static bool ffa_tee_enabled;

bool vm_supports_indirect_messages(struct vm *vm)
{
	return vm->ffa_version >= FFA_VERSION_1_1 &&
	       vm_supports_messaging_method(vm, FFA_PARTITION_INDIRECT_MSG);
}

struct ffa_value plat_ffa_spmc_id_get(void)
{
	if (ffa_tee_enabled) {
		/*
		 * Fetch the SPMC ID from the SPMD using FFA_SPM_ID_GET.
		 * DEN0077A FF-A v1.1 Beta0 section 13.9.2
		 * "FFA_SPM_ID_GET invocation at a non-secure physical FF-A
		 * instance returns the ID of the SPMC."
		 */
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

void plat_ffa_set_tee_enabled(bool tee_enabled)
{
	ffa_tee_enabled = tee_enabled;
}

static void plat_ffa_rxtx_map_spmc(paddr_t recv, paddr_t send,
				   uint64_t page_count)
{
	struct ffa_value ret;

	ret = arch_other_world_call((struct ffa_value){.func = FFA_RXTX_MAP_64,
						       .arg1 = pa_addr(recv),
						       .arg2 = pa_addr(send),
						       .arg3 = page_count});
	CHECK(ret.func == FFA_SUCCESS_32);
}

void plat_ffa_init(struct mpool *ppool)
{
	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct ffa_value ret;
	struct mm_stage1_locked mm_stage1_locked;

	/* This is a segment from TDRAM for the NS memory in the FVP platform.
	 *
	 * TODO: We ought to provide a better way to do this, if porting the
	 * hypervisor to other platforms. One option would be to provide this
	 * via DTS.
	 */
	const uint64_t start = 0x90000000;
	const uint64_t len = 0x60000000;
	const paddr_t send_addr = pa_init(start + len - PAGE_SIZE * 1);
	const paddr_t recv_addr = pa_init(start + len - PAGE_SIZE * 2);

	(void)ppool;

	if (!ffa_tee_enabled) {
		return;
	}

	CHECK(other_world_vm != NULL);

	arch_ffa_init();

	/*
	 * Call FFA_VERSION so the SPMC can store the hypervisor's
	 * version. This may be useful if there is a mismatch of
	 * versions.
	 */
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_VERSION_32, .arg1 = FFA_VERSION_COMPILED});
	if (ret.func == (uint32_t)FFA_NOT_SUPPORTED) {
		panic("Hypervisor and SPMC versions are not compatible.\n");
	}

	/*
	 * Setup TEE VM RX/TX buffers.
	 * Using the following hard-coded addresses, as they must be within the
	 * NS memory node in the SPMC manifest. From that region we should
	 * exclude the Hypervisor's address space to prevent SPs from using that
	 * memory in memory region nodes, or for the NWd to misuse that memory
	 * in runtime via memory sharing interfaces.
	 */

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	other_world_vm->mailbox.send = (void *)pa_addr(send_addr);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	other_world_vm->mailbox.recv = (void *)pa_addr(recv_addr);

	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	plat_ffa_rxtx_map_spmc(
		pa_from_va(va_from_ptr(other_world_vm->mailbox.recv)),
		pa_from_va(va_from_ptr(other_world_vm->mailbox.send)),
		HF_MAILBOX_SIZE / FFA_PAGE_SIZE);

	ffa_tee_enabled = true;

	/*
	 * Hypervisor will write to secure world receive buffer, and will read
	 * from the secure world send buffer.
	 *
	 * Mapping operation is necessary because the ranges are outside of the
	 * hypervisor's binary.
	 */
	mm_stage1_locked = mm_lock_stage1();
	CHECK(mm_identity_map(mm_stage1_locked, send_addr,
			      pa_add(send_addr, PAGE_SIZE),
			      MM_MODE_R | MM_MODE_SHARED, ppool) != NULL);
	CHECK(mm_identity_map(
		      mm_stage1_locked, recv_addr, pa_add(recv_addr, PAGE_SIZE),
		      MM_MODE_R | MM_MODE_W | MM_MODE_SHARED, ppool) != NULL);
	mm_unlock_stage1(&mm_stage1_locked);

	dlog_verbose("TEE finished setting up buffers.\n");
}

bool plat_ffa_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	/*
	 * VM's requests should be forwarded to the SPMC, if target is an SP.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		*ret = arch_other_world_call_ext((struct ffa_value){
			.func = FFA_RUN_32, ffa_vm_vcpu(vm_id, vcpu_idx)});
		return true;
	}

	return false;
}

/**
 * Check validity of the FF-A memory send function attempt.
 */
bool plat_ffa_is_memory_send_valid(ffa_id_t receiver, ffa_id_t sender,
				   uint32_t share_func, bool multiple_borrower)
{
	/*
	 * Currently memory interfaces are not forwarded from hypervisor to
	 * SPMC. However, in absence of SPMC this function should allow
	 * NS-endpoint to SP memory send in order for trusty tests to work.
	 */

	(void)share_func;
	(void)receiver;
	(void)sender;
	(void)multiple_borrower;

	return true;
}

/**
 * Check validity of a FF-A direct message request.
 */
bool plat_ffa_is_direct_request_valid(struct vcpu *current,
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

/**
 * Check validity of the calls:
 * FFA_NOTIFICATION_BITMAP_CREATE/FFA_NOTIFICATION_BITMAP_DESTROY.
 */
struct ffa_value plat_ffa_is_notifications_bitmap_access_valid(
	struct vcpu *current, ffa_id_t vm_id)
{
	/*
	 * Call should only be used by the Hypervisor, so any attempt of
	 * invocation from NWd FF-A endpoints should fail.
	 */
	(void)current;
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm, uint32_t func)
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
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
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

bool plat_ffa_direct_request_forward(ffa_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret)
{
	if (!ffa_tee_enabled) {
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

bool plat_ffa_rx_release_forward(struct vm_locked vm_locked,
				 struct ffa_value *ret)
{
	struct vm *vm = vm_locked.vm;
	ffa_id_t vm_id = vm->id;

	if (!ffa_tee_enabled || !vm_supports_indirect_messages(vm)) {
		return false;
	}

	CHECK(vm_id_is_current_world(vm_id));

	/* Hypervisor always forward VM's RX_RELEASE to SPMC. */
	*ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_RX_RELEASE_32, .arg1 = vm_id});

	if (ret->func == FFA_SUCCESS_32) {
		/*
		 * The SPMC owns the VM's RX buffer after a successful
		 * FFA_RX_RELEASE call.
		 */
		vm->mailbox.state = MAILBOX_STATE_OTHER_WORLD_OWNED;
	} else {
		dlog_verbose("FFA_RX_RELEASE forwarded failed for VM ID %#x.\n",
			     vm_locked.vm->id);
	}

	return true;
}

/**
 * Acquire the RX buffer of a VM from the SPM.
 *
 * VM RX/TX buffers must have been previously mapped in the SPM either
 * by forwarding VM's RX_TX_MAP API or another way if buffers were
 * declared in manifest.
 *
 * Returns true if the ownership belongs to the hypervisor.
 */
bool plat_ffa_acquire_receiver_rx(struct vm_locked to_locked,
				  struct ffa_value *ret)
{
	struct ffa_value other_world_ret;

	/*
	 * Do not forward the call if either:
	 * - The TEE is not present.
	 * - The VM's version is not FF-A v1.1.
	 * - If the mailbox ownership hasn't been transferred to the SPMC.
	 */
	if (!ffa_tee_enabled || !vm_supports_indirect_messages(to_locked.vm) ||
	    to_locked.vm->mailbox.state != MAILBOX_STATE_OTHER_WORLD_OWNED) {
		return true;
	}

	other_world_ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RX_ACQUIRE_32, .arg1 = to_locked.vm->id});

	if (ret != NULL) {
		*ret = other_world_ret;
	}

	if (other_world_ret.func == FFA_SUCCESS_32) {
		to_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;
	}

	return other_world_ret.func == FFA_SUCCESS_32;
}

bool plat_ffa_intercept_call(struct vcpu_locked current_locked,
			     struct vcpu_locked next_locked,
			     struct ffa_value *signal_interrupt)
{
	(void)current_locked;
	(void)next_locked;
	(void)signal_interrupt;

	return false;
}

bool plat_ffa_is_indirect_msg_supported(struct vm_locked sender_locked,
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

bool plat_ffa_msg_send2_forward(ffa_id_t receiver_vm_id, ffa_id_t sender_vm_id,
				struct ffa_value *ret)
{
	/* FFA_MSG_SEND2 is forwarded to SPMC when the receiver is an SP. */
	if (!vm_id_is_current_world(receiver_vm_id)) {
		/*
		 * Set the sender in arg1 to allow the SPMC to retrieve
		 * VM's TX buffer to copy in SP's RX buffer.
		 */
		*ret = arch_other_world_call((struct ffa_value){
			.func = FFA_MSG_SEND2_32, .arg1 = sender_vm_id << 16});
		if (ffa_func_id(*ret) != FFA_SUCCESS_32) {
			dlog_verbose(
				"Failed forwarding FFA_MSG_SEND2_32 to the "
				"SPMC, got error (%lu).\n",
				ret->arg2);
		}

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

uint32_t plat_ffa_other_world_mode(void)
{
	return 0U;
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_id_t caller_id, const struct vm *target)
{
	ffa_partition_properties_t result = target->messaging_method;
	/*
	 * VMs support indirect messaging only in the Normal World.
	 * Primary VM cannot receive direct requests.
	 * Secondary VMs cannot send direct requests.
	 */
	if (!vm_id_is_current_world(caller_id)) {
		result &= ~FFA_PARTITION_INDIRECT_MSG;
	}
	if (vm_is_primary(target)) {
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
					  ffa_id_t sender_id,
					  ffa_id_t receiver_id)
{
	ffa_id_t current_vm_id = current->vm->id;
	/** If Hafnium is hypervisor, receiver needs to be current vm. */
	return sender_id != receiver_id && current_vm_id == receiver_id;
}

bool plat_ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret)
{
	CHECK(ret != NULL);

	if (vm_id_is_current_world(receiver_id) &&
	    !vm_id_is_current_world(sender_id)) {
		dlog_verbose(
			"Forward notifications bind/unbind to other world.\n");
		*ret = arch_other_world_call((struct ffa_value){
			.func = is_bind ? FFA_NOTIFICATION_BIND_32
					: FFA_NOTIFICATION_UNBIND_32,
			.arg1 = (sender_id << 16) | (receiver_id),
			.arg2 = is_bind ? flags : 0U,
			.arg3 = (uint32_t)(bitmap),
			.arg4 = (uint32_t)(bitmap >> 32),
		});
		return true;
	}
	return false;
}

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_id_t sender_id,
					ffa_id_t receiver_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	/* If Hafnium is hypervisor, sender needs to be current vm. */
	return sender_id == current_vm_id && sender_id != receiver_id;
}

bool plat_ffa_notification_set_forward(ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id, uint32_t flags,
				       ffa_notifications_bitmap_t bitmap,
				       struct ffa_value *ret)
{
	/* Forward only if receiver is an SP. */
	if (vm_id_is_current_world(receiver_vm_id)) {
		return false;
	}

	dlog_verbose("Forwarding notification set to SPMC.\n");

	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_SET_32,
		.arg1 = (sender_vm_id << 16) | receiver_vm_id,
		.arg2 = flags & ~FFA_NOTIFICATIONS_FLAG_DELAY_SRI,
		.arg3 = (uint32_t)(bitmap),
		.arg4 = (uint32_t)(bitmap >> 32),
	});

	if (ret->func == FFA_ERROR_32) {
		dlog_verbose("Failed to set notifications from SPMC.\n");
	}

	return true;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_id_t receiver_id, uint32_t flags)
{
	ffa_id_t current_vm_id = current->vm->id;

	(void)flags;

	/* If Hafnium is hypervisor, receiver needs to be current vm. */
	return (current_vm_id == receiver_id);
}

struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool plat_ffa_notifications_bitmap_create_call(ffa_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count)
{
	struct ffa_value ret;

	if (ffa_tee_enabled) {
		ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_BITMAP_CREATE_32,
			.arg1 = vm_id,
			.arg2 = vcpu_count,
		});

		if (ret.func == FFA_ERROR_32) {
			dlog_error(
				"Failed to create notifications bitmap "
				"to VM: %#x; error: %#x.\n",
				vm_id, ffa_error_code(ret));
			return false;
		}
	}

	return true;
}

struct vm_locked plat_ffa_vm_find_locked(ffa_id_t vm_id)
{
	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	return (struct vm_locked){.vm = NULL};
}

struct vm_locked plat_ffa_vm_find_locked_create(ffa_id_t vm_id)
{
	return plat_ffa_vm_find_locked(vm_id);
}

void plat_ffa_notification_info_get_forward(uint16_t *ids, uint32_t *ids_count,
					    uint32_t *lists_sizes,
					    uint32_t *lists_count,
					    const uint32_t ids_count_max)
{
	CHECK(ids != NULL);
	CHECK(ids_count != NULL);
	CHECK(lists_sizes != NULL);
	CHECK(lists_count != NULL);
	CHECK(ids_count_max == FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

	uint32_t local_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS];
	struct ffa_value ret;

	dlog_verbose("Forwarding notification info get to SPMC.\n");

	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_INFO_GET_64,
	});

	if (ret.func == FFA_ERROR_32) {
		dlog_verbose("No notifications returned by SPMC.\n");
		return;
	}

	*lists_count = ffa_notification_info_get_lists_count(ret);

	if (*lists_count > ids_count_max) {
		*lists_count = 0;
		return;
	}

	/*
	 * The count of ids should be at least the number of lists, to
	 * encompass for at least the ids of the FF-A endpoints. List
	 * sizes will be between 0 and 3, and relates to the counting of
	 * vCPU of the endpoint that have pending notifications.
	 * If `lists_count` is already ids_count_max, each list size
	 * must be 0.
	 */
	*ids_count = *lists_count;

	for (uint32_t i = 0; i < *lists_count; i++) {
		local_lists_sizes[i] =
			ffa_notification_info_get_list_size(ret, i + 1);

		/*
		 * ... sum the counting of each list size that are part
		 * of the main list.
		 */
		*ids_count += local_lists_sizes[i];
	}

	/*
	 * Sanity check returned `lists_count` and determined
	 * `ids_count`. If something wrong, reset arguments to 0 such
	 * that hypervisor's handling of FFA_NOTIFICATION_INFO_GET can
	 * proceed without SPMC's values.
	 */
	if (*ids_count > ids_count_max) {
		*ids_count = 0;
		return;
	}

	/* Copy now lists sizes, as return sizes have been validated. */
	memcpy_s(lists_sizes, sizeof(lists_sizes[0]) * ids_count_max,
		 local_lists_sizes, FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

	/* Unpack the notifications info from the return. */
	memcpy_s(ids, sizeof(ids[0]) * ids_count_max, &ret.arg3,
		 sizeof(ret.arg3) * FFA_NOTIFICATIONS_INFO_GET_REGS_RET);
}

bool plat_ffa_notifications_get_from_sp(struct vm_locked receiver_locked,
					ffa_vcpu_index_t vcpu_id,
					ffa_notifications_bitmap_t *from_sp,
					struct ffa_value *ret)
{
	ffa_id_t receiver_id = receiver_locked.vm->id;

	assert(from_sp != NULL && ret != NULL);

	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_GET_32,
		.arg1 = (vcpu_id << 16) | receiver_id,
		.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SP,
	});

	if (ret->func == FFA_ERROR_32) {
		return false;
	}

	*from_sp = ffa_notification_get_from_sp(*ret);

	return true;
}

bool plat_ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	uint32_t flags, ffa_vcpu_index_t vcpu_id, struct ffa_value *ret)
{
	ffa_id_t receiver_id = receiver_locked.vm->id;
	ffa_notifications_bitmap_t spm_notifications = 0;

	(void)flags;

	assert(from_fwk != NULL);
	assert(ret != NULL);

	/* Get SPMC notifications. */
	if (ffa_tee_enabled) {
		*ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_GET_32,
			.arg1 = (vcpu_id << 16) | receiver_id,
			.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SPM,
		});

		if (ffa_func_id(*ret) == FFA_ERROR_32) {
			return false;
		}

		spm_notifications = ffa_notification_get_from_framework(*ret);
	}

	/* Merge notifications from SPMC and Hypervisor. */
	*from_fwk = spm_notifications |
		    vm_notifications_framework_get_pending(receiver_locked);

	return true;
}

bool plat_ffa_vm_notifications_info_get(     // NOLINTNEXTLINE
	uint16_t *ids, uint32_t *ids_count,  // NOLINTNEXTLINE
	uint32_t *lists_sizes,		     // NOLINTNEXTLINE
	uint32_t *lists_count, const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;

	return false;
}

void plat_ffa_rxtx_map_forward(struct vm_locked vm_locked)
{
	struct vm *vm = vm_locked.vm;
	struct vm *other_world;

	if (!ffa_tee_enabled) {
		vm_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;
		return;
	}

	if (!vm_supports_indirect_messages(vm)) {
		return;
	}

	/* Hypervisor always forward the call to the SPMC. */

	other_world = vm_find(HF_OTHER_WORLD_ID);

	/* Fill the buffers descriptor in SPMC's RX buffer. */
	ffa_endpoint_rx_tx_descriptor_init(
		(struct ffa_endpoint_rx_tx_descriptor *)
			other_world->mailbox.recv,
		vm->id, (uintptr_t)vm->mailbox.recv,
		(uintptr_t)vm->mailbox.send);

	plat_ffa_rxtx_map_spmc(pa_init(0), pa_init(0), 0);

	vm_locked.vm->mailbox.state = MAILBOX_STATE_OTHER_WORLD_OWNED;

	dlog_verbose("Mailbox of %x owned by SPMC.\n", vm_locked.vm->id);
}

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked)
{
	/* Hypervisor never frees VM structs. */
	(void)to_destroy_locked;
}

void plat_ffa_rxtx_unmap_forward(struct vm_locked vm_locked)
{
	struct ffa_value ret;
	uint64_t func;
	ffa_id_t id;

	assert(vm_locked.vm != NULL);

	id = vm_locked.vm->id;

	if (!ffa_tee_enabled) {
		return;
	}

	if (!vm_supports_indirect_messages(vm_locked.vm)) {
		return;
	}

	/* Hypervisor always forwards forward RXTX_UNMAP to SPMC. */
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_RXTX_UNMAP_32,
				   .arg1 = id << FFA_RXTX_ALLOCATOR_SHIFT});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == (uint64_t)SMCCC_ERROR_UNKNOWN) {
		panic("Unknown error forwarding RXTX_UNMAP.\n");
	} else if (func == FFA_ERROR_32) {
		panic("Error %d forwarding RX/TX buffers.\n", ret.arg2);
	} else if (func != FFA_SUCCESS_32) {
		panic("Unexpected function %#x returned forwarding RX/TX "
		      "buffers.",
		      ret.func);
	}
}

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current)
{
	(void)current;
	return has_vhe_support();
}

bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current)
{
	(void)current;
	return has_vhe_support();
}

/**
 * Check if current VM can resume target VM/SP using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu_locked current_locked,
			 ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			 struct ffa_value *run_ret, struct vcpu **next)
{
	(void)next;
	(void)vcpu_idx;

	/* Only the primary VM can switch vCPUs. */
	if (!vm_is_primary(current_locked.vcpu->vm)) {
		run_ret->arg2 = FFA_DENIED;
		return false;
	}

	/* Only secondary VM vCPUs can be run. */
	if (target_vm_id == HF_PRIMARY_VM_ID) {
		return false;
	}

	return true;
}

void plat_ffa_handle_secure_interrupt(struct vcpu *current, struct vcpu **next)
{
	(void)current;
	(void)next;

	/*
	 * SPMD uses FFA_INTERRUPT ABI to convey secure interrupt to
	 * SPMC. Execution should not reach hypervisor with this ABI.
	 */
	CHECK(false);
}

/**
 * An Hypervisor should send the SRI to the Primary Endpoint. Not implemented
 * as Hypervisor is only interesting for us for the sake of having a test
 * intrastructure that encompasses the NWd, and we are not interested on
 * in testing the flow of notifications between VMs only.
 */
void plat_ffa_sri_trigger_if_delayed(struct cpu *cpu)
{
	(void)cpu;
}

void plat_ffa_sri_trigger_not_delayed(struct cpu *cpu)
{
	(void)cpu;
}

/**
 * Track that in current CPU there was a notification set with delay SRI
 * flag.
 */
void plat_ffa_sri_set_delayed(struct cpu *cpu)
{
	(void)cpu;
}

bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vcpu_locked current_locked,
	struct vm_locked receiver_locked)
{
	(void)target_locked;
	(void)current_locked;
	(void)receiver_locked;

	return false;
}

bool plat_ffa_partition_info_get_regs_forward_allowed(void)
{
	/*
	 * Allow forwarding from the Hypervisor if TEE or SPMC exists and
	 * declared as such in the Hypervisor manifest.
	 */
	return ffa_tee_enabled;
}

/*
 * Forward helper for FFA_PARTITION_INFO_GET.
 * Emits FFA_PARTITION_INFO_GET from Hypervisor to SPMC if allowed.
 */
void plat_ffa_partition_info_get_forward(const struct ffa_uuid *uuid,
					 const uint32_t flags,
					 struct ffa_partition_info *partitions,
					 ffa_vm_count_t *ret_count)
{
	const struct vm *tee = vm_find(HF_TEE_VM_ID);
	struct ffa_partition_info *tee_partitions;
	ffa_vm_count_t tee_partitions_count;
	ffa_vm_count_t vm_count = *ret_count;
	struct ffa_value ret;

	CHECK(tee != NULL);
	CHECK(vm_count < MAX_VMS);

	/*
	 * Allow forwarding from the Hypervisor if TEE or SPMC exists and
	 * declared as such in the Hypervisor manifest.
	 */
	if (!ffa_tee_enabled) {
		return;
	}

	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_PARTITION_INFO_GET_32,
				   .arg1 = uuid->uuid[0],
				   .arg2 = uuid->uuid[1],
				   .arg3 = uuid->uuid[2],
				   .arg4 = uuid->uuid[3],
				   .arg5 = flags});
	if (ffa_func_id(ret) != FFA_SUCCESS_32) {
		dlog_verbose(
			"Failed forwarding FFA_PARTITION_INFO_GET to "
			"the SPMC.\n");
		return;
	}

	tee_partitions_count = ffa_partition_info_get_count(ret);
	if (tee_partitions_count == 0 || tee_partitions_count > MAX_VMS) {
		dlog_verbose("Invalid number of SPs returned by the SPMC.\n");
		return;
	}

	if ((flags & FFA_PARTITION_COUNT_FLAG_MASK) ==
	    FFA_PARTITION_COUNT_FLAG) {
		vm_count += tee_partitions_count;
	} else {
		tee_partitions = (struct ffa_partition_info *)tee->mailbox.send;
		for (ffa_vm_count_t index = 0; index < tee_partitions_count;
		     index++) {
			partitions[vm_count] = tee_partitions[index];
			++vm_count;
		}

		/* Release the RX buffer. */
		ret = arch_other_world_call(
			(struct ffa_value){.func = FFA_RX_RELEASE_32});
		CHECK(ret.func == FFA_SUCCESS_32);
	}

	*ret_count = vm_count;
}

void plat_ffa_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
				       paddr_t fdt_addr,
				       size_t fdt_allocated_size,
				       const struct manifest_vm *manifest_vm,
				       const struct boot_params *boot_params,
				       struct mpool *ppool)
{
	struct fdt partition_fdt;

	/*
	 * If the partition is an FF-A partition and is not
	 * hypervisor loaded, the manifest is passed in the
	 * partition package and is parsed during
	 * manifest_init() and secondary fdt should be empty.
	 */
	CHECK(manifest_vm->is_hyp_loaded);
	CHECK(mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_allocated_size), MM_MODE_R,
			      ppool) != NULL);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	CHECK(fdt_init_from_ptr(&partition_fdt, (void *)pa_addr(fdt_addr),
				fdt_allocated_size) == true);
	CHECK(parse_ffa_manifest(&partition_fdt,
				 (struct manifest_vm *)manifest_vm, NULL,
				 boot_params) == MANIFEST_SUCCESS);
	CHECK(mm_unmap(stage1_locked, fdt_addr,
		       pa_add(fdt_addr, fdt_allocated_size), ppool) == true);
}

/**
 * Returns FFA_ERROR as FFA_SECONDARY_EP_REGISTER is not supported at the
 * non-secure FF-A instances.
 */
bool plat_ffa_is_secondary_ep_register_supported(void)
{
	return false;
}

/**
 * The invocation of FFA_MSG_WAIT at non-secure virtual FF-A instance is made
 * to be compliant with version v1.0 of the FF-A specification. It serves as
 * a blocking call.
 */
struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu_locked current_locked,
					   struct vcpu **next)
{
	return plat_ffa_msg_recv(true, current_locked, next);
}

/**
 * Checks whether the vCPU's attempt to block for a message has already been
 * interrupted or whether it is allowed to block.
 */
static bool plat_ffa_msg_recv_block_interrupted(
	struct vcpu_locked current_locked)
{
	bool interrupted;

	/*
	 * Don't block if there are enabled and pending interrupts, to match
	 * behaviour of wait_for_interrupt.
	 */
	interrupted = (vcpu_interrupt_count_get(current_locked) > 0);

	return interrupted;
}

/**
 * Returns true if there is something in the return code, either a v1.0
 * FFA_MSG_SEND, or an FFA_ERROR.
 */
static bool plat_ffa_return_pending_messages(struct vm_locked vm_locked,
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
struct ffa_value plat_ffa_msg_recv(bool block,
				   struct vcpu_locked current_locked,
				   struct vcpu **next)
{
	bool is_direct_request_ongoing;
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
	is_direct_request_ongoing =
		is_ffa_direct_msg_request_ongoing(current_locked);

	if (is_direct_request_ongoing) {
		return ffa_error(FFA_DENIED);
	}

	vcpu_unlock(&current_locked);
	vm_locked = vm_lock(vm);
	current_locked = vcpu_lock(current);

	if (plat_ffa_return_pending_messages(vm_locked, &return_code)) {
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
	if (plat_ffa_msg_recv_block_interrupted(current_locked)) {
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

bool plat_ffa_check_runtime_state_transition(struct vcpu_locked current_locked,
					     ffa_id_t vm_id,
					     ffa_id_t receiver_vm_id,
					     struct vcpu_locked receiver_locked,
					     uint32_t func,
					     enum vcpu_state *next_state)
{
	(void)current_locked;
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_locked;

	switch (func) {
	case FFA_YIELD_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
	case FFA_RUN_32:
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		*next_state = VCPU_STATE_WAITING;
		return true;
	default:
		return false;
	}
}

void plat_ffa_init_schedule_mode_ffa_run(struct vcpu_locked current_locked,
					 struct vcpu_locked target_locked)
{
	/* Scheduling mode not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)target_locked;
}

void plat_ffa_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)receiver_vcpu_locked;
	(void)sender_vm_id;
}

bool plat_ffa_is_spmd_lp_id(ffa_id_t vm_id)
{
	(void)vm_id;
	return false;
}

void plat_ffa_unwind_call_chain_ffa_direct_resp(
	struct vcpu_locked current_locked, struct vcpu_locked next_locked)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)next_locked;
}

/**
 * Enable relevant virtual interrupts for VMs.
 */
void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;

	if (vm_locked.vm->notifications.enabled) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_NOTIFICATION_PENDING_INTID);
	}
}

/** Forwards a memory send message on to the other world. */
static struct ffa_value memory_send_other_world_forward(
	struct vm_locked other_world_locked, uint32_t share_func,
	struct ffa_memory_region *memory_region, uint32_t memory_share_length,
	uint32_t fragment_length)
{
	struct ffa_value ret;

	/* Use its own RX buffer. */
	memcpy_s(other_world_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 memory_region, fragment_length);

	other_world_locked.vm->mailbox.recv_func = share_func;
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_FULL;
	ret = arch_other_world_call(
		(struct ffa_value){.func = share_func,
				   .arg1 = memory_share_length,
				   .arg2 = fragment_length});
	/*
	 * After the call to the other world completes it must have finished
	 * reading its RX buffer, so it is ready for another message.
	 */
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Validates a call to donate, lend or share memory to the other world and then
 * updates the stage-2 page tables. Specifically, check if the message length
 * and number of memory region constituents match, and if the transition is
 * valid for the type of memory sending operation.
 *
 * Assumes that the caller has already found and locked the sender VM and the
 * other world VM, and copied the memory region descriptor from the sender's TX
 * buffer to a freshly allocated page from Hafnium's internal pool. The caller
 * must have also validated that the receiver VM ID is valid.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
static struct ffa_value ffa_memory_other_world_send(
	struct vm_locked from_locked, struct vm_locked to_locked,
	struct ffa_memory_region *memory_region, uint32_t memory_share_length,
	uint32_t fragment_length, uint32_t share_func, struct mpool *page_pool)
{
	ffa_memory_handle_t handle;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_value reclaim_ret;
	(void)reclaim_ret;

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(from_locked, memory_region,
				       memory_share_length, fragment_length,
				       share_func);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_err;
	}

	share_states = share_states_lock();

	if (fragment_length == memory_share_length) {
		/* No more fragments to come, everything fits in one message. */

		/* Forward memory send message on to other world. */
		ret = memory_send_other_world_forward(
			to_locked, share_func, memory_region,
			memory_share_length, fragment_length);
		if (ret.func != FFA_SUCCESS_32) {
			dlog_verbose(
				"%s: failed to forward memory send message to "
				"other world: %s(%s).\n",
				__func__, ffa_func_name(ret.func),
				ffa_error_name(ffa_error_code(ret)));
			goto out;
		}

		handle = ffa_mem_success_handle(ret);
		share_state = allocate_share_state(share_states, share_func,
						   memory_region,
						   fragment_length, handle);
		if (share_state == NULL) {
			dlog_verbose("%s: failed to allocate share state.\n",
				     __func__);
			ret = ffa_error(FFA_NO_MEMORY);

			reclaim_ret = arch_other_world_call((struct ffa_value){
				.func = FFA_MEM_RECLAIM_32,
				.arg1 = (uint32_t)handle,
				.arg2 = (uint32_t)(handle >> 32),
				.arg3 = 0});
			assert(reclaim_ret.func == FFA_SUCCESS_32);
			goto out;
		}

		ret = ffa_memory_send_complete(from_locked, share_states,
					       share_state, page_pool,
					       &share_state->sender_orig_mode);
		if (ret.func != FFA_SUCCESS_32) {
			dlog_verbose(
				"%s: failed to complete memory send: %s(%s).\n",
				__func__, ffa_func_name(ret.func),
				ffa_error_name(ffa_error_code(ret)));

			reclaim_ret = arch_other_world_call((struct ffa_value){
				.func = FFA_MEM_RECLAIM_32,
				.arg1 = (uint32_t)handle,
				.arg2 = (uint32_t)(handle >> 32),
				.arg3 = 0});
			assert(reclaim_ret.func == FFA_SUCCESS_32);
			goto out;
		}
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	} else {
		/* More fragments remaining, fragmented message. */
		dlog_verbose("%s: more fragments remaining: %d/%d\n", __func__,
			     fragment_length, memory_share_length);

		/*
		 * We need to wait for the rest of the fragments before we can
		 * check whether the transaction is valid and unmap the memory.
		 * Call the other world so it can do its initial validation and
		 * assign a handle, and allocate a share state to keep what we
		 * have so far.
		 */
		ret = memory_send_other_world_forward(
			to_locked, share_func, memory_region,
			memory_share_length, fragment_length);
		if (ret.func != FFA_MEM_FRAG_RX_32) {
			dlog_warning(
				"%s: failed to forward to other world: "
				"%s(%s)\n",
				__func__, ffa_func_name(ret.func),
				ffa_error_name(ffa_error_code(ret)));
			goto out;
		}
		if (ret.func != FFA_MEM_FRAG_RX_32) {
			dlog_warning(
				"%s: got unexpected response to %s "
				"from other world (expected %s, got %s)\n",
				__func__, ffa_func_name(share_func),
				ffa_func_name(FFA_MEM_FRAG_RX_32),
				ffa_func_name(ret.func));
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}
		if (ret.arg3 != fragment_length) {
			dlog_warning(
				"%s: got unexpected fragment offset for %s "
				"from other world (expected %d, got %lu)\n",
				__func__, ffa_func_name(FFA_MEM_FRAG_RX_32),
				fragment_length, ret.arg3);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}
		if (ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_warning(
				"%s: got unexpected sender ID for %s from "
				"other world (expected %d, got %d)\n",
				__func__, ffa_func_name(FFA_MEM_FRAG_RX_32),
				from_locked.vm->id, ffa_frag_sender(ret));
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}
		handle = ffa_frag_handle(ret);
		share_state = allocate_share_state(share_states, share_func,
						   memory_region,
						   fragment_length, handle);
		if (share_state == NULL) {
			dlog_verbose("%s: failed to allocate share state.\n",
				     __func__);
			ret = ffa_error(FFA_NO_MEMORY);

			reclaim_ret = arch_other_world_call((struct ffa_value){
				.func = FFA_MEM_RECLAIM_32,
				.arg1 = (uint32_t)handle,
				.arg2 = (uint32_t)(handle >> 32),
				.arg3 = 0});
			assert(reclaim_ret.func == FFA_SUCCESS_32);
			goto out;
		}
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)handle,
			.arg2 = (uint32_t)(handle >> 32),
			.arg3 = fragment_length,
		};
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	}

out:
	share_states_unlock(&share_states);
out_err:
	if (memory_region != NULL) {
		mpool_free(page_pool, memory_region);
	}
	return ret;
}

struct ffa_value plat_ffa_other_world_mem_send(
	struct vm *from, uint32_t share_func,
	struct ffa_memory_region **memory_region, uint32_t length,
	uint32_t fragment_length, struct mpool *page_pool)
{
	struct vm *to;
	struct ffa_value ret;

	to = vm_find(HF_OTHER_WORLD_ID);

	/*
	 * The 'to' VM lock is only needed in the case that it is the
	 * TEE VM.
	 */
	struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

	/* Check if the `to` VM has the mailbox busy. */
	if (vm_is_mailbox_busy(vm_to_from_lock.vm1)) {
		dlog_verbose("The other world VM has a message. %x\n",
			     vm_to_from_lock.vm1.vm->id);
		ret = ffa_error(FFA_BUSY);
	} else {
		ret = ffa_memory_other_world_send(
			vm_to_from_lock.vm2, vm_to_from_lock.vm1,
			*memory_region, length, fragment_length, share_func,
			page_pool);
		/*
		 * ffa_other_world_memory_send takes ownership of the
		 * memory_region, so make sure we don't free it.
		 */
		*memory_region = NULL;
	}

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
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

/**
 * Validates that the reclaim transition is allowed for the memory region with
 * the given handle which was previously shared with the SPMC. Tells the
 * SPMC to mark it as reclaimed, and updates the page table of the reclaiming
 * VM.
 *
 * To do this information about the memory region is first fetched from the
 * SPMC.
 */
static struct ffa_value ffa_memory_other_world_reclaim(
	struct vm_locked to_locked, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;
	struct ffa_value ret;

	dump_share_states();

	share_states = share_states_lock();

	share_state = get_share_state(share_states, handle);
	if (share_state == NULL) {
		dlog_verbose("Unable to find share state for handle %#lx.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}
	memory_region = share_state->memory_region;

	CHECK(memory_region != NULL);

	if (vm_id_is_current_world(to_locked.vm->id) &&
	    to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %#x attempted to reclaim memory handle %#lx "
			"originally sent by VM %#x.\n",
			to_locked.vm->id, handle, memory_region->sender);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->sending_complete) {
		dlog_verbose(
			"Memory with handle %#lx not fully sent, can't "
			"reclaim.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	for (uint32_t i = 0; i < memory_region->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			ffa_memory_region_get_receiver(memory_region, i);
		struct ffa_memory_region_attributes receiver_permissions;

		CHECK(receiver != NULL);

		receiver_permissions = receiver->receiver_permissions;

		/* Skip the entries that relate to SPs. */
		if (!ffa_is_vm_id(receiver_permissions.receiver)) {
			continue;
		}

		/* Check that all VMs have relinquished. */
		if (share_state->retrieved_fragment_count[i] != 0) {
			dlog_verbose(
				"Tried to reclaim memory handle %#lx "
				"that has not been relinquished by all "
				"borrowers(%x).\n",
				handle, receiver_permissions.receiver);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}
	}

	/*
	 * Call to the SPMC, for it to free the memory state tracking
	 * structures. This can fail if the SPs haven't finished using the
	 * memory.
	 */
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_RECLAIM_32,
				   .arg1 = (uint32_t)handle,
				   .arg2 = (uint32_t)(handle >> 32),
				   .arg3 = flags});

	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose(
			"FFA_MEM_RECLAIM returned an error. Expected "
			"FFA_SUCCESS, got %s (%s)\n",
			ffa_func_name(ret.func), ffa_error_name(ret.arg2));
		goto out;
	}

	/*
	 * Masking the CLEAR flag, as this operation was expected to have been
	 * done by the SPMC.
	 */
	flags &= ~FFA_MEMORY_REGION_FLAG_CLEAR;
	ret = ffa_retrieve_check_update(
		to_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, share_state->sender_orig_mode,
		FFA_MEM_RECLAIM_32, flags & FFA_MEM_RECLAIM_CLEAR, page_pool,
		NULL, false);

	if (ret.func == FFA_SUCCESS_32) {
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state after successful reclaim.\n");
	}

out:
	share_states_unlock(&share_states);
	return ret;
}

struct ffa_value plat_ffa_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	struct ffa_value ret;
	struct vm *from = vm_find(HF_TEE_VM_ID);
	struct two_vm_locked vm_to_from_lock;

	if (!ffa_tee_enabled) {
		dlog_verbose("Invalid handle %#lx for FFA_MEM_RECLAIM.\n",
			     handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	vm_to_from_lock = vm_lock_both(to, from);

	ret = ffa_memory_other_world_reclaim(vm_to_from_lock.vm1, handle, flags,
					     page_pool);

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}

/**
 * Forwards a memory send continuation message on to the other world.
 */
static struct ffa_value memory_send_continue_other_world_forward(
	struct vm_locked other_world_locked, ffa_id_t sender_vm_id,
	void *fragment, uint32_t fragment_length, ffa_memory_handle_t handle)
{
	struct ffa_value ret;

	memcpy_s(other_world_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 fragment, fragment_length);

	other_world_locked.vm->mailbox.recv_func = FFA_MEM_FRAG_TX_32;
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_FULL;
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_FRAG_TX_32,
				   .arg1 = (uint32_t)handle,
				   .arg2 = (uint32_t)(handle >> 32),
				   .arg3 = fragment_length,
				   .arg4 = (uint64_t)sender_vm_id << 16});

	/*
	 * After the call to the other world completes it must have finished
	 * reading its RX buffer, so it is ready for another message.
	 */
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Continues an operation to donate, lend or share memory to the other world VM.
 * If this is the last fragment then checks that the transition is valid for the
 * type of memory sending operation and updates the stage-2 page tables of the
 * sender.
 *
 * Assumes that the caller has already found and locked the sender VM and copied
 * the memory region descriptor from the sender's TX buffer to a freshly
 * allocated page from Hafnium's internal pool.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
static struct ffa_value ffa_memory_other_world_send_continue(
	struct vm_locked from_locked, struct vm_locked to_locked,
	void *fragment, uint32_t fragment_length, ffa_memory_handle_t handle,
	struct mpool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;

	ret = ffa_memory_send_continue_validate(share_states, handle,
						&share_state,
						from_locked.vm->id, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_free_fragment;
	}
	memory_region = share_state->memory_region;

	if (!memory_region_receivers_from_other_world(memory_region)) {
		dlog_error(
			"Got SPM-allocated handle for memory send to non-other "
			"world VM. This should never happen, and indicates a "
			"bug.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_free_fragment;
	}

	if (to_locked.vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	    to_locked.vm->mailbox.recv == NULL) {
		/*
		 * If the other_world RX buffer is not available, tell the
		 * sender to retry by returning the current offset again.
		 */
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)handle,
			.arg2 = (uint32_t)(handle >> 32),
			.arg3 = share_state_next_fragment_offset(share_states,
								 share_state),
		};
		goto out_free_fragment;
	}

	/* Add this fragment. */
	share_state->fragments[share_state->fragment_count] = fragment;
	share_state->fragment_constituent_counts[share_state->fragment_count] =
		fragment_length / sizeof(struct ffa_memory_region_constituent);
	share_state->fragment_count++;

	/* Check whether the memory send operation is now ready to complete. */
	if (share_state_sending_complete(share_states, share_state)) {
		struct mpool local_page_pool;

		/*
		 * Use a local page pool so that we can roll back if necessary.
		 */
		mpool_init_with_fallback(&local_page_pool, page_pool);

		ret = ffa_memory_send_complete(from_locked, share_states,
					       share_state, &local_page_pool,
					       &share_state->sender_orig_mode);

		if (ret.func == FFA_SUCCESS_32) {
			/*
			 * Forward final fragment on to the other_world so that
			 * it can complete the memory sending operation.
			 */
			ret = memory_send_continue_other_world_forward(
				to_locked, from_locked.vm->id, fragment,
				fragment_length, handle);

			if (ret.func != FFA_SUCCESS_32) {
				/*
				 * The error will be passed on to the caller,
				 * but log it here too.
				 */
				dlog_verbose(
					"other_world didn't successfully "
					"complete "
					"memory send operation; returned %#lx "
					"(%lu). Rolling back.\n",
					ret.func, ret.arg2);

				/*
				 * The other_world failed to complete the send
				 * operation, so roll back the page table update
				 * for the VM. This can't fail because it won't
				 * try to allocate more memory than was freed
				 * into the `local_page_pool` by
				 * `ffa_send_check_update` in the initial
				 * update.
				 */
				CHECK(ffa_region_group_identity_map(
					      from_locked,
					      share_state->fragments,
					      share_state
						      ->fragment_constituent_counts,
					      share_state->fragment_count,
					      share_state->sender_orig_mode,
					      &local_page_pool,
					      MAP_ACTION_COMMIT, NULL)
					      .func == FFA_SUCCESS_32);
			}
		} else {
			/* Abort sending to other_world. */
			struct ffa_value other_world_ret =
				arch_other_world_call((struct ffa_value){
					.func = FFA_MEM_RECLAIM_32,
					.arg1 = (uint32_t)handle,
					.arg2 = (uint32_t)(handle >> 32)});

			if (other_world_ret.func != FFA_SUCCESS_32) {
				/*
				 * Nothing we can do if other_world doesn't
				 * abort properly, just log it.
				 */
				dlog_verbose(
					"other_world didn't successfully abort "
					"failed memory send operation; "
					"returned %#lx %lu).\n",
					other_world_ret.func,
					other_world_ret.arg2);
			}
			/*
			 * We don't need to free the share state in this case
			 * because ffa_memory_send_complete does that already.
			 */
		}

		mpool_fini(&local_page_pool);
	} else {
		uint32_t next_fragment_offset =
			share_state_next_fragment_offset(share_states,
							 share_state);

		ret = memory_send_continue_other_world_forward(
			to_locked, from_locked.vm->id, fragment,
			fragment_length, handle);

		if (ret.func != FFA_MEM_FRAG_RX_32 ||
		    ffa_frag_handle(ret) != handle ||
		    ret.arg3 != next_fragment_offset ||
		    ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_verbose(
				"Got unexpected result from forwarding "
				"FFA_MEM_FRAG_TX to other_world: %#lx (handle "
				"%#lx, offset %lu, sender %d); expected "
				"FFA_MEM_FRAG_RX (handle %#lx, offset %d, "
				"sender %d).\n",
				ret.func, ffa_frag_handle(ret), ret.arg3,
				ffa_frag_sender(ret), handle,
				next_fragment_offset, from_locked.vm->id);
			/* Free share state. */
			share_state_free(share_states, share_state, page_pool);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		ret = (struct ffa_value){.func = FFA_MEM_FRAG_RX_32,
					 .arg1 = (uint32_t)handle,
					 .arg2 = (uint32_t)(handle >> 32),
					 .arg3 = next_fragment_offset};
	}
	goto out;

out_free_fragment:
	mpool_free(page_pool, fragment);

out:
	share_states_unlock(&share_states);
	return ret;
}

struct ffa_value plat_ffa_other_world_mem_send_continue(
	struct vm *from, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct mpool *page_pool)
{
	struct ffa_value ret;
	struct vm *to = vm_find(HF_TEE_VM_ID);
	struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

	/*
	 * The TEE RX buffer state is checked in
	 * `ffa_memory_other_world_send_continue` rather than here, as
	 * we need to return `FFA_MEM_FRAG_RX` with the current offset
	 * rather than FFA_ERROR FFA_BUSY in case it is busy.
	 */

	ret = ffa_memory_other_world_send_continue(
		vm_to_from_lock.vm2, vm_to_from_lock.vm1, fragment,
		fragment_length, handle, page_pool);
	/*
	 * `ffa_memory_other_world_send_continue` takes ownership of the
	 * fragment_copy, so we don't need to free it here.
	 */

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}

/*
 * Copies data from the sender's send buffer to the recipient's receive buffer
 * and notifies the recipient.
 *
 * If the recipient's receive buffer is busy, it can optionally register the
 * caller to be notified when the recipient's receive buffer becomes available.
 */
struct ffa_value plat_ffa_msg_send(ffa_id_t sender_vm_id,
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

/*
 * Prepare to yield execution back to the VM that allocated cpu cycles and move
 * to BLOCKED state.
 */
struct ffa_value plat_ffa_yield_prepare(struct vcpu_locked current_locked,
					struct vcpu **next,
					uint32_t timeout_low,
					uint32_t timeout_high)
{
	struct vcpu *current = current_locked.vcpu;
	struct ffa_value ret = {
		.func = FFA_YIELD_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
		.arg2 = timeout_low,
		.arg3 = timeout_high,
	};

	/*
	 * Return execution to primary VM.
	 */
	*next = api_switch_to_primary(current_locked, ret, VCPU_STATE_BLOCKED);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

ffa_memory_attributes_t plat_ffa_memory_security_mode(
	ffa_memory_attributes_t attributes, uint32_t mode)
{
	(void)mode;

	return attributes;
}

struct ffa_value plat_ffa_error_32(struct vcpu *current, struct vcpu **next,
				   enum ffa_error error_code)
{
	(void)current;
	(void)next;
	(void)error_code;
	/* TODO: Interface not handled in hypervisor. */
	return ffa_error(FFA_NOT_SUPPORTED);
}

void plat_ffa_free_vm_resources(struct vm_locked vm_locked)
{
	(void)vm_locked;
}

uint32_t plat_ffa_interrupt_get(struct vcpu_locked current_locked)
{
	return api_interrupt_get(current_locked);
}

bool plat_ffa_handle_framework_msg(struct ffa_value args, struct ffa_value *ret)
{
	(void)args;
	(void)ret;

	return false;
}
