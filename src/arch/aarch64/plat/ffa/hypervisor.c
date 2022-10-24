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
#include "hf/std.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "msr.h"
#include "smc.h"
#include "sysregs.h"

static bool ffa_tee_enabled;

alignas(FFA_PAGE_SIZE) static uint8_t other_world_send_buffer[HF_MAILBOX_SIZE];
alignas(FFA_PAGE_SIZE) static uint8_t other_world_recv_buffer[HF_MAILBOX_SIZE];

/** Returns information on features specific to the NWd. */
struct ffa_value plat_ffa_features(uint32_t function_feature_id)
{
	switch (function_feature_id) {
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

	/* Setup TEE VM RX/TX buffers */
	other_world_vm->mailbox.send = &other_world_send_buffer;
	other_world_vm->mailbox.recv = &other_world_recv_buffer;

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
 * Check validity of the FF-A memory send function attempt.
 */
bool plat_ffa_is_memory_send_valid(ffa_vm_id_t receiver_vm_id,
				   uint32_t share_func)
{
	/*
	 * Currently memory interfaces are not forwarded from hypervisor to
	 * SPMC. However, in absence of SPMC this function should allow
	 * NS-endpoint to SP memory send in order for trusty tests to work.
	 */

	(void)share_func;
	(void)receiver_vm_id;
	return true;
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

bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm)
{
	(void)sender_vm;
	(void)receiver_vm;

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
	if (!vm_id_is_current_world(receiver_vm_id)) {
		dlog_verbose("%s calling SPMC %#x %#x %#x %#x %#x\n", __func__,
			     args.func, args.arg1, args.arg2, args.arg3,
			     args.arg4);
		*ret = arch_other_world_call(args);
		return true;
	}

	return false;
}

bool plat_ffa_rx_release_forward(struct vm_locked vm_locked,
				 struct ffa_value *ret)
{
	struct vm *vm = vm_locked.vm;
	ffa_vm_id_t vm_id = vm->id;

	if (!ffa_tee_enabled || (vm->ffa_version < MAKE_FFA_VERSION(1, 1))) {
		*ret = (struct ffa_value){.func = FFA_SUCCESS_32};
		return true;
	}

	CHECK(vm_id_is_current_world(vm_id));

	/* Hypervisor always forward VM's RX_RELEASE to SPMC. */
	*ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_RX_RELEASE_32, .arg1 = vm_id});

	return ret->func == FFA_SUCCESS_32;
}

/**
 * In FF-A v1.1 with SPMC enabled the SPMC owns the RX buffers for NWd VMs,
 * hence the SPMC is handling FFA_RX_RELEASE calls for NWd VMs too.
 * The Hypervisor's view of a VM's RX buffer can be out of sync, reset it to
 * 'empty' if the FFA_RX_RELEASE call has been successfully forwarded to the
 * SPMC.
 */
bool plat_ffa_rx_release_forwarded(struct vm_locked vm_locked)
{
	struct vm *vm = vm_locked.vm;

	if (ffa_tee_enabled && (vm->ffa_version > MAKE_FFA_VERSION(1, 0))) {
		dlog_verbose(
			"RX_RELEASE forwarded, reset MB state for VM ID %#x.\n",
			vm->id);
		vm->mailbox.state = MAILBOX_STATE_EMPTY;
		return true;
	}

	return false;
}

/**
 * Acquire the RX buffer of a VM from the SPM.
 *
 * VM RX/TX buffers must have been previously mapped in the SPM either
 * by forwarding VM's RX_TX_MAP API or another way if buffers were
 * declared in manifest.
 */
bool plat_ffa_acquire_receiver_rx(struct vm_locked to_locked,
				  struct ffa_value *ret)
{
	if (!ffa_tee_enabled) {
		return true;
	}

	if (to_locked.vm->ffa_version < MAKE_FFA_VERSION(1, 1)) {
		return true;
	}

	*ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RX_ACQUIRE_32, .arg1 = to_locked.vm->id});

	return ret->func == FFA_SUCCESS_32;
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

bool plat_ffa_msg_send2_forward(ffa_vm_id_t receiver_vm_id,
				ffa_vm_id_t sender_vm_id, struct ffa_value *ret)
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
				"SPMC, got error (%d).\n",
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

uint32_t plat_ffa_owner_world_mode(ffa_vm_id_t owner_id)
{
	(void)owner_id;
	return plat_ffa_other_world_mode();
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

bool plat_ffa_notifications_update_bindings_forward(
	ffa_vm_id_t receiver_id, ffa_vm_id_t sender_id, uint32_t flags,
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
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/* If Hafnium is hypervisor, sender needs to be current vm. */
	return sender_id == current_vm_id && sender_id != receiver_id;
}

bool plat_ffa_notification_set_forward(ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id,
				       uint32_t flags,
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
		.arg2 = flags,
		.arg3 = (uint32_t)(bitmap),
		.arg4 = (uint32_t)(bitmap >> 32),
	});

	if (ret->func == FFA_ERROR_32) {
		dlog_verbose("Failed to set notifications from SPMC.\n");
	}

	return true;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id, uint32_t flags)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	(void)flags;

	/* If Hafnium is hypervisor, receiver needs to be current vm. */
	return (current_vm_id == receiver_id);
}

struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool plat_ffa_notifications_bitmap_create_call(ffa_vm_id_t vm_id,
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

struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id)
{
	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	return (struct vm_locked){.vm = NULL};
}

struct vm_locked plat_ffa_vm_find_locked_create(ffa_vm_id_t vm_id)
{
	return plat_ffa_vm_find_locked(vm_id);
}

bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id)
{
	return vm_id_is_current_world(vm_id);
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
	ffa_vm_id_t receiver_id = receiver_locked.vm->id;

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
	ffa_vm_id_t receiver_id = receiver_locked.vm->id;
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
		return;
	}

	if (vm->ffa_version < MAKE_FFA_VERSION(1, 1)) {
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
}

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked)
{
	/* Hypervisor never frees VM structs. */
	(void)to_destroy_locked;
}

void plat_ffa_rxtx_unmap_forward(ffa_vm_id_t id)
{
	struct ffa_value ret;
	uint64_t func;

	if (!ffa_tee_enabled) {
		return;
	}

	/* Hypervisor always forwards forward RXTX_UNMAP to SPMC. */
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RXTX_UNMAP_32, .arg1 = id << 16});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == SMCCC_ERROR_UNKNOWN) {
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
bool plat_ffa_run_checks(struct vcpu *current, ffa_vm_id_t target_vm_id,
			 ffa_vcpu_index_t vcpu_idx, struct ffa_value *run_ret,
			 struct vcpu **next)
{
	(void)next;
	(void)vcpu_idx;

	/* Only the primary VM can switch vCPUs. */
	if (current->vm->id != HF_PRIMARY_VM_ID) {
		run_ret->arg2 = FFA_DENIED;
		return false;
	}

	/* Only secondary VM vCPUs can be run. */
	if (target_vm_id == HF_PRIMARY_VM_ID) {
		return false;
	}

	return true;
}

struct ffa_value plat_ffa_handle_secure_interrupt(struct vcpu *current,
						  struct vcpu **next,
						  bool from_normal_world)
{
	(void)current;
	(void)next;
	(void)from_normal_world;

	/*
	 * SPMD uses FFA_INTERRUPT ABI to convey secure interrupt to
	 * SPMC. Execution should not reach hypervisor with this ABI.
	 */
	CHECK(false);

	return ffa_error(FFA_NOT_SUPPORTED);
}

void plat_ffa_sri_state_set(enum plat_ffa_sri_state state)
{
	(void)state;
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

void plat_ffa_sri_init(struct cpu *cpu)
{
	(void)cpu;
}

bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vcpu *current,
	struct vm_locked receiver_locked)
{
	(void)target_locked;
	(void)current;
	(void)receiver_locked;

	return false;
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

	if ((flags && FFA_PARTITION_COUNT_FLAG_MASK) ==
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
				 (struct manifest_vm *)manifest_vm,
				 NULL) == MANIFEST_SUCCESS);
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
struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu *current,
					   struct vcpu **next)
{
	return api_ffa_msg_recv(true, current, next);
}

bool plat_ffa_check_runtime_state_transition(
	struct vcpu *current, ffa_vm_id_t vm_id, ffa_vm_id_t receiver_vm_id,
	struct vcpu *receiver_vcpu, uint32_t func, enum vcpu_state *next_state)
{
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_vcpu;

	switch (func) {
	case FFA_YIELD_32:
		/* Check if a direct message is ongoing. */
		if (current->direct_request_origin_vm_id != HF_INVALID_VM_ID) {
			return false;
		}

		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_RUN_32:
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
		*next_state = VCPU_STATE_WAITING;
		return true;
	default:
		return false;
	}
}

void plat_ffa_init_schedule_mode_ffa_run(struct vcpu *current,
					 struct vcpu_locked target_locked)
{
	/* Scheduling mode not supported in the Hypervisor/VMs. */
	(void)current;
	(void)target_locked;
}

void plat_ffa_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)receiver_vcpu_locked;
}

void plat_ffa_unwind_call_chain_ffa_direct_resp(struct vcpu *current,
						struct vcpu *next)
{
	/* Calls chains not supported in the Hypervisor/VMs. */
	(void)current;
	(void)next;
}

void plat_ffa_enable_virtual_maintenance_interrupts(
	struct vcpu_locked current_locked)
{
	(void)current_locked;
}
