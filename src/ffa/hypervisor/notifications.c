/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/notifications.h"

#include "hf/arch/other_world.h"

#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/ffa/init.h"
#include "hf/ffa_internal.h"
#include "hf/std.h"
#include "hf/vm.h"

/**
 * Check validity of the calls:
 * FFA_NOTIFICATION_BITMAP_CREATE/FFA_NOTIFICATION_BITMAP_DESTROY.
 */
struct ffa_value ffa_notifications_is_bitmap_access_valid(struct vcpu *current,
							  ffa_id_t vm_id)
{
	/*
	 * Call should only be used by the Hypervisor, so any attempt of
	 * invocation from NWd FF-A endpoints should fail.
	 */
	(void)current;
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool ffa_notifications_is_bind_valid(struct vcpu *current, ffa_id_t sender_id,
				     ffa_id_t receiver_id)
{
	ffa_id_t current_vm_id = current->vm->id;
	/** If Hafnium is hypervisor, receiver needs to be current vm. */
	return sender_id != receiver_id && current_vm_id == receiver_id;
}

bool ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id,
	ffa_notification_flags_t flags, ffa_notifications_bitmap_t bitmap,
	bool is_bind, struct ffa_value *ret)
{
	CHECK(ret != NULL);

	if (vm_id_is_current_world(receiver_id) &&
	    !vm_id_is_current_world(sender_id)) {
		dlog_verbose(
			"Forward notifications bind/unbind to other world.\n");
		*ret = arch_other_world_call((struct ffa_value){
			.func = is_bind ? FFA_NOTIFICATION_BIND_32
					: FFA_NOTIFICATION_UNBIND_32,
			.arg1 = ((uint64_t)sender_id << 16) | receiver_id,
			.arg2 = is_bind ? flags : 0U,
			.arg3 = ffa_notification_bitmap_low32(bitmap),
			.arg4 = ffa_notification_bitmap_high32(bitmap),
		});
		return true;
	}
	return false;
}

bool ffa_notifications_update_bindings2_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id, uint64_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret)
{
	CHECK(ret != NULL);

	/*
	 * When Hafnium is the hypervisor, an SP-to-VM notification binding
	 * must be forwarded to the SPMC. The VM is the receiver in the
	 * hypervisor's world, while the SP sender belongs to the other world.
	 */
	if (vm_id_is_current_world(receiver_id) &&
	    !vm_id_is_current_world(sender_id)) {
		struct ffa_value args = {
			.func = is_bind ? FFA_NOTIFICATION_BIND2_64
					: FFA_NOTIFICATION_UNBIND2_64,
			.arg1 = ((uint64_t)sender_id << 16) | receiver_id,
			.arg2 = is_bind ? flags : 0U,
			.extended_val.valid = true,
		};

		dlog_verbose(
			"Forward notifications bind2/unbind2 to other "
			"world.\n");

		/* BIND2 and UNBIND2 carry the 384-bit bitmap in x3-x8. */
		ffa_notification_bitmap_to_regs(
			bitmap, &args.arg3, &args.arg4, &args.arg5, &args.arg6,
			&args.arg7, &args.extended_val.arg8);

		*ret = arch_other_world_call_ext(args);

		/* The request was handled by the other FF-A world. */
		return true;
	}
	/* Continue handling the binding locally. */
	return false;
}

bool ffa_notifications_is_set_valid(struct vcpu *current, ffa_id_t sender_id,
				    ffa_id_t receiver_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	/* If Hafnium is hypervisor, sender needs to be current vm. */
	return sender_id == current_vm_id && sender_id != receiver_id;
}

bool ffa_notifications_set_forward(ffa_id_t sender_vm_id,
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
		.arg1 = ((uint64_t)sender_vm_id << 16) | receiver_vm_id,
		.arg2 = flags & ~FFA_NOTIFICATIONS_FLAG_DELAY_SRI,
		.arg3 = ffa_notification_bitmap_low32(bitmap),
		.arg4 = ffa_notification_bitmap_high32(bitmap),
	});

	if (ret->func == FFA_ERROR_32) {
		dlog_verbose("Failed to set notifications from SPMC.\n");
	}

	return true;
}

bool ffa_notifications_set2_forward(struct ffa_value request,
				    struct ffa_value *ret)
{
	if (vm_id_is_current_world(ffa_receiver(request))) {
		return false;
	}

	dlog_verbose("Forwarding notification set2 to SPMC.\n");

	request.arg2 &= ~FFA_NOTIFICATIONS_FLAG_DELAY_SRI;
	*ret = arch_other_world_call_ext(request);

	return true;
}

bool ffa_notifications_is_get_valid(struct vcpu *current, ffa_id_t receiver_id,
				    ffa_notification_flags_t flags)
{
	ffa_id_t current_vm_id = current->vm->id;

	(void)flags;

	/* If Hafnium is hypervisor, receiver needs to be current vm. */
	return (current_vm_id == receiver_id);
}

struct ffa_value ffa_notifications_bitmap_create(ffa_id_t vm_id,
						 ffa_vcpu_count_t vcpu_count,
						 uint16_t notification_count)
{
	(void)vm_id;
	(void)vcpu_count;
	(void)notification_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value ffa_notifications_bitmap_destroy(ffa_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool ffa_notifications_bitmap_create_call(
	ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count,
	uint16_t requested_notification_count,
	uint16_t *allocated_notification_count)
{
	struct ffa_value ret;

	CHECK(allocated_notification_count != NULL);
	CHECK(requested_notification_count >= FFA_NOTIFICATION_COUNT_BASE);
	CHECK(requested_notification_count <= MAX_FFA_NOTIFICATIONS);

	*allocated_notification_count = requested_notification_count;

	if (ffa_init_is_tee_enabled()) {
		ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_BITMAP_CREATE_32,
			.arg1 = vm_id,
			.arg2 = vcpu_count,
			.arg3 = FFA_NOTIFICATION_COUNT_ENCODE(
				requested_notification_count),
		});

		return ffa_notifications_bitmap_create_process_response(
			vm_id, requested_notification_count, ret,
			allocated_notification_count);
	}
	return true;
}

void ffa_notifications_info_get_forward(uint16_t *ids, uint32_t *ids_count,
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

struct ffa_value ffa_notifications_get_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	ffa_notifications_bitmap_t *from_sp)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	ffa_id_t receiver_id = receiver_locked.vm->id;

	assert(from_sp != NULL);

	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_NOTIFICATION_GET_32,
		.arg1 = ((uint64_t)vcpu_id << 16) | receiver_id,
		.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SP,
	});

	if (ret.func == FFA_ERROR_32) {
		return ret;
	}

	*from_sp = ffa_notification_get_from_sp(ret);

	return ret;
}

struct ffa_value ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	ffa_notification_flags_t flags, ffa_vcpu_index_t vcpu_id)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	ffa_id_t receiver_id = receiver_locked.vm->id;
	ffa_notifications_bitmap_t spm_notifications;

	(void)flags;

	assert(from_fwk != NULL);

	ffa_notification_bitmap_init(&spm_notifications);
	/* Get SPMC notifications. */
	if (ffa_init_is_tee_enabled()) {
		ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_GET_32,
			.arg1 = ((uint64_t)vcpu_id << 16) | receiver_id,
			.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SPM,
		});

		if (ffa_func_id(ret) == FFA_ERROR_32) {
			return ret;
		}

		spm_notifications = ffa_notification_get_from_framework(ret);
	}

	/* Merge notifications from SPMC and Hypervisor. */
	*from_fwk = ffa_notification_bitmap_or(
		spm_notifications,
		vm_notifications_framework_get_pending(receiver_locked));

	return ret;
}

struct ffa_value ffa_notifications_get2_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_spm,
	ffa_notifications_bitmap_t *from_hyp,
	ffa_notifications_bitmap_t spm_mask,
	ffa_notifications_bitmap_t hyp_mask, ffa_notification_flags_t flags,
	ffa_vcpu_index_t vcpu_id)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	ffa_id_t receiver_id = receiver_locked.vm->id;

	assert(from_spm != NULL);
	assert(from_hyp != NULL);

	ffa_notification_bitmap_init(from_spm);
	ffa_notification_bitmap_init(from_hyp);

	/* SPMC framework notifications come from the other world. */
	if ((flags & FFA_NOTIFICATION_FLAG_BITMAP_SPM) != 0U &&
	    ffa_init_is_tee_enabled()) {
		/*
		 * Use GET2 to support x15 selective retrieval mask for SPM
		 * framework notifications. Returned bitmap is in x15.
		 */
		ret = arch_other_world_call_ext((struct ffa_value){
			.func = FFA_NOTIFICATION_GET2_64,
			.arg1 = ((uint64_t)vcpu_id << 16) | receiver_id,
			.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SPM,
			.arg3 = 0U,
			.arg4 = 0U,
			.arg5 = 0U,
			.arg6 = 0U,
			.arg7 = 0U,
			.extended_val.arg8 = 0U,
			.extended_val.arg15 =
				ffa_notification_bitmap_low64(spm_mask),
			.extended_val.arg16 = 0U,
			.extended_val.arg17 = 0U,
			.extended_val.valid = true,
		});
		if (ffa_func_id(ret) == FFA_ERROR_32) {
			return ret;
		}
		*from_spm = ffa_notification_bitmap_from_legacy_u64(
			ret.extended_val.arg15);
	}

	/* Hypervisor framework notifications are local. */
	if ((flags & FFA_NOTIFICATION_FLAG_BITMAP_HYP) != 0U) {
		*from_hyp = vm_notifications_framework_get_pending_masked(
			receiver_locked, true, hyp_mask);
	}

	return ret;
}

struct ffa_value ffa_notifications_get2_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	ffa_notifications_bitmap_t mask, ffa_notifications_bitmap_t *from_sp)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	ffa_id_t receiver_id = receiver_locked.vm->id;

	struct ffa_value args = {
		.func = FFA_NOTIFICATION_GET2_64,
		.arg1 = ((uint64_t)vcpu_id << 16) | receiver_id,
		.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SP,
		.extended_val.arg15 = 0U,
		.extended_val.arg16 = 0U,
		.extended_val.arg17 = 0U,
		.extended_val.valid = true,
	};
	assert(from_sp != NULL);

	ffa_notification_bitmap_to_regs(mask, &args.arg3, &args.arg4,
					&args.arg5, &args.arg6, &args.arg7,
					&args.extended_val.arg8);
	/*
	 * GET2 requires x8.. registers, so use the _ext call and mark
	 * extended_val.valid.
	 */
	ret = arch_other_world_call_ext(args);

	if (ret.func == FFA_ERROR_32) {
		return ret;
	}

	*from_sp = ffa_notification_bitmap_from_get2_sp(ret);
	return ret;
}

/**
 * A hypervisor should send the SRI to the Primary Endpoint. Not implemented as
 * the hypervisor is only interesting for us for the sake of having a test
 * intrastructure that encompasses the NWd, and we are not interested in testing
 * the flow of notifications between VMs only.
 */
void ffa_notifications_sri_trigger_if_delayed(struct cpu *cpu)
{
	(void)cpu;
}

void ffa_notifications_sri_trigger_not_delayed(struct cpu *cpu)
{
	(void)cpu;
}

/**
 * Track that in current CPU there was a notification set with delay SRI
 * flag.
 */
void ffa_notifications_sri_set_delayed(struct cpu *cpu)
{
	(void)cpu;
}
