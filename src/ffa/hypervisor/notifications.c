/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/notifications.h"

#include "hf/arch/other_world.h"

#include "hf/ffa_internal.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "hypervisor.h"

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
			.arg1 = (sender_id << 16) | (receiver_id),
			.arg2 = is_bind ? flags : 0U,
			.arg3 = (uint32_t)(bitmap),
			.arg4 = (uint32_t)(bitmap >> 32),
		});
		return true;
	}
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

bool ffa_notifications_is_get_valid(struct vcpu *current, ffa_id_t receiver_id,
				    ffa_notification_flags_t flags)
{
	ffa_id_t current_vm_id = current->vm->id;

	(void)flags;

	/* If Hafnium is hypervisor, receiver needs to be current vm. */
	return (current_vm_id == receiver_id);
}

struct ffa_value ffa_notifications_bitmap_create(ffa_id_t vm_id,
						 ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value ffa_notifications_bitmap_destroy(ffa_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool ffa_notifications_bitmap_create_call(ffa_id_t vm_id,
					  ffa_vcpu_count_t vcpu_count)
{
	struct ffa_value ret;

	if (plat_ffa_is_tee_enabled()) {
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
		.arg1 = (vcpu_id << 16) | receiver_id,
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
	ffa_notifications_bitmap_t spm_notifications = 0;

	(void)flags;

	assert(from_fwk != NULL);

	/* Get SPMC notifications. */
	if (plat_ffa_is_tee_enabled()) {
		ret = arch_other_world_call((struct ffa_value){
			.func = FFA_NOTIFICATION_GET_32,
			.arg1 = (vcpu_id << 16) | receiver_id,
			.arg2 = FFA_NOTIFICATION_FLAG_BITMAP_SPM,
		});

		if (ffa_func_id(ret) == FFA_ERROR_32) {
			return ret;
		}

		spm_notifications = ffa_notification_get_from_framework(ret);
	}

	/* Merge notifications from SPMC and Hypervisor. */
	*from_fwk = spm_notifications |
		    vm_notifications_framework_get_pending(receiver_locked);

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
