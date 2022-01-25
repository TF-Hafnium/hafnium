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
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

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
	struct ffa_value ret = arch_other_world_call((struct ffa_value){
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

	return true;
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
	CHECK(from_sp != NULL && ret != NULL);

	ffa_vm_id_t receiver_id = receiver_locked.vm->id;

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

struct ffa_value plat_ffa_delegate_ffa_interrupt(struct vcpu *current,
						 struct vcpu **next)
{
	(void)current;
	(void)next;

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
	CHECK(sanity_check_ffa_manifest((struct manifest_vm *)manifest_vm) ==
	      MANIFEST_SUCCESS);
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

bool plat_ffa_msg_wait_prepare(struct vcpu *current, struct vcpu **next,
			       struct ffa_value *ret_args)
{
	(void)current;
	(void)next;
	(void)ret_args;

	return false;
}
