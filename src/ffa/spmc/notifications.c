/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/notifications.h"

#include <stdint.h>

#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/ffa.h"
#include "hf/ffa/direct_messaging.h"
#include "hf/ffa/vm.h"
#include "hf/ffa_internal.h"
#include "hf/plat/interrupts.h"
#include "hf/types.h"
#include "hf/vm.h"

#include "./vm.h"

/** Interrupt priority for the Schedule Receiver Interrupt. */
#define SRI_PRIORITY UINT32_C(0xf0)

struct ffa_value ffa_notifications_is_bitmap_access_valid(struct vcpu *current,
							  ffa_id_t vm_id)
{
	/**
	 * Create/Destroy interfaces to be called by the hypervisor, into the
	 * SPMC.
	 */
	if (current->vm->id != HF_HYPERVISOR_VM_ID) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	/* ID provided must be a valid VM ID. */
	if (!ffa_is_vm_id(vm_id)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	return (struct ffa_value){
		.func = FFA_SUCCESS_32,
	};
}

/**
 * - A bind call cannot be from an SPMD logical partition or target an
 * SPMD logical partition.
 * - If bind call from SP, receiver's ID must be same as current VM ID.
 * - If bind call from NWd, current VM ID must be same as Hypervisor ID,
 * receiver's ID must be from NWd, and sender's ID from SWd.
 */
bool ffa_notifications_is_bind_valid(struct vcpu *current, ffa_id_t sender_id,
				     ffa_id_t receiver_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	if (ffa_direct_msg_is_spmd_lp_id(sender_id) ||
	    ffa_direct_msg_is_spmd_lp_id(receiver_id)) {
		dlog_verbose(
			"Notification bind: not permitted for logical SPs (%x "
			"%x).\n",
			sender_id, receiver_id);
		return false;
	}

	if (sender_id == receiver_id) {
		dlog_verbose(
			"Notification set: sender can't target itself. (%x == "
			"%x)\n",
			sender_id, receiver_id);
		return false;
	}

	/* Caller is an SP. */
	if (vm_id_is_current_world(current_vm_id)) {
		if (receiver_id != current_vm_id) {
			dlog_verbose(
				"Notification bind: caller (%x) must be the "
				"receiver(%x).\n",
				current_vm_id, receiver_id);
			return false;
		}
	} else {
		assert(current_vm_id == HF_HYPERVISOR_VM_ID);

		if (!vm_id_is_current_world(sender_id) ||
		    vm_id_is_current_world(receiver_id)) {
			dlog_verbose(
				"Notification bind: VM must specify itself as "
				"receiver (%x), and SP as sender(%x).\n",
				receiver_id, sender_id);
			return false;
		}
	}

	return true;
}

bool ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id,
	ffa_notification_flags_t flags, ffa_notifications_bitmap_t bitmap,
	bool is_bind, struct ffa_value *ret)
{
	(void)ret;
	(void)receiver_id;
	(void)sender_id;
	(void)flags;
	(void)bitmap;
	(void)is_bind;
	(void)ret;

	return false;
}

/*
 * - A set call cannot be from an SPMD logical partition or target an
 * SPMD logical partition.
 * - If set call from SP, sender's ID must be the same as current.
 * - If set call from NWd, current VM ID must be same as Hypervisor ID,
 * and receiver must be an SP.
 */
bool ffa_notifications_is_set_valid(struct vcpu *current, ffa_id_t sender_id,
				    ffa_id_t receiver_id)
{
	ffa_id_t current_vm_id = current->vm->id;

	if (ffa_direct_msg_is_spmd_lp_id(sender_id) ||
	    ffa_direct_msg_is_spmd_lp_id(receiver_id)) {
		dlog_verbose(
			"Notification set: not permitted for logical SPs (%x "
			"%x).\n",
			sender_id, receiver_id);
		return false;
	}

	if (sender_id == receiver_id) {
		dlog_verbose(
			"Notification set: sender can't target itself. (%x == "
			"%x)\n",
			sender_id, receiver_id);
		return false;
	}

	if (vm_id_is_current_world(current_vm_id)) {
		if (sender_id != current_vm_id) {
			dlog_verbose(
				"Notification set: caller (%x) must be the "
				"sender(%x).\n",
				current_vm_id, sender_id);
			return false;
		}
	} else {
		assert(current_vm_id == HF_HYPERVISOR_VM_ID);

		if (vm_id_is_current_world(sender_id) ||
		    !vm_id_is_current_world(receiver_id)) {
			dlog_verbose(
				"Notification set: sender (%x) must be a VM "
				"and receiver (%x) an SP.\n",
				sender_id, receiver_id);
			return false;
		}
	}

	return true;
}

bool ffa_notifications_set_forward(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id,
				   ffa_notification_flags_t flags,
				   ffa_notifications_bitmap_t bitmap,
				   struct ffa_value *ret)
{
	(void)sender_vm_id;
	(void)receiver_vm_id;
	(void)flags;
	(void)bitmap;
	(void)ret;

	return false;
}

bool ffa_notifications_is_get_valid(struct vcpu *current, ffa_id_t receiver_id,
				    ffa_notification_flags_t flags)
{
	ffa_id_t current_vm_id = current->vm->id;
	/*
	 * SPMC:
	 * - A get call cannot be targeted to an SPMD logical partition.
	 * - An SP can ask for its notifications, or the hypervisor can get
	 *  notifications target to a VM.
	 */
	bool caller_and_receiver_valid =
		(!ffa_direct_msg_is_spmd_lp_id(receiver_id) &&
		 (current_vm_id == receiver_id)) ||
		(current_vm_id == HF_HYPERVISOR_VM_ID &&
		 !vm_id_is_current_world(receiver_id));

	/*
	 * Flags field is not valid if NWd endpoint requests notifications from
	 * VMs or Hypervisor. Those are managed by the hypervisor if present.
	 */
	bool flags_valid =
		!(ffa_is_vm_id(receiver_id) &&
		  ((flags & FFA_NOTIFICATION_FLAG_BITMAP_VM) != 0U ||
		   (flags & FFA_NOTIFICATION_FLAG_BITMAP_HYP) != 0U));

	return caller_and_receiver_valid && flags_valid;
}

void ffa_notifications_info_get_forward(     // NOLINTNEXTLINE
	uint16_t *ids, uint32_t *ids_count,  // NOLINTNEXTLINE
	uint32_t *lists_sizes, uint32_t *lists_count,
	const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;
}

struct ffa_value ffa_notifications_bitmap_create(ffa_id_t vm_id,
						 ffa_vcpu_count_t vcpu_count)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vm_locked vm_locked;

	if (vm_id == HF_OTHER_WORLD_ID) {
		/*
		 * If the provided VM ID regards to the Hypervisor, represented
		 * by the other world VM with ID HF_OTHER_WORLD_ID, check if the
		 * notifications have been enabled.
		 */

		vm_locked = vm_find_locked(vm_id);

		CHECK(vm_locked.vm != NULL);

		/* Call has been used for the other world vm already */
		if (vm_locked.vm->notifications.enabled) {
			dlog_verbose("Notification bitmap already created.\n");
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		/* Enable notifications for `other_world_vm`. */
		vm_locked.vm->notifications.enabled = true;
	} else {
		/* Else should regard with NWd VM ID. */
		vm_locked = ffa_vm_nwd_create(vm_id);

		/* If received NULL, there are no slots for VM creation. */
		if (vm_locked.vm == NULL) {
			dlog_verbose("No memory to create VM ID %#x.\n", vm_id);
			return ffa_error(FFA_NO_MEMORY);
		}

		/* Ensure bitmap has not already been created. */
		if (vm_locked.vm->notifications.enabled) {
			dlog_verbose("Notification bitmap already created.\n");
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		vm_locked.vm->notifications.enabled = true;
		vm_locked.vm->vcpu_count = vcpu_count;
	}

out:
	vm_unlock(&vm_locked);

	return ret;
}

bool ffa_notifications_bitmap_create_call(ffa_id_t vm_id,
					  ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return true;
}

struct ffa_value ffa_notifications_bitmap_destroy(ffa_id_t vm_id)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	struct vm_locked to_destroy_locked = ffa_vm_find_locked(vm_id);

	if (to_destroy_locked.vm == NULL) {
		dlog_verbose("Bitmap not created for VM: %u\n", vm_id);
		return ffa_error(FFA_DENIED);
	}

	if (!to_destroy_locked.vm->notifications.enabled) {
		dlog_verbose("Notification disabled for VM: %u\n", vm_id);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/* Check if there is any notification pending. */
	if (vm_are_notifications_pending(to_destroy_locked, false, ~0x0U)) {
		dlog_verbose("VM has notifications pending.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	to_destroy_locked.vm->notifications.enabled = false;
	vm_notifications_init(to_destroy_locked.vm,
			      to_destroy_locked.vm->vcpu_count, NULL);
	if (vm_id != HF_OTHER_WORLD_ID) {
		ffa_vm_destroy(to_destroy_locked);
	}

out:
	vm_unlock(&to_destroy_locked);

	return ret;
}

struct ffa_value ffa_notifications_get_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	ffa_notifications_bitmap_t *from_sp)
{
	*from_sp = vm_notifications_partition_get_pending(receiver_locked,
							  false, vcpu_id);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	ffa_notification_flags_t flags, ffa_vcpu_index_t vcpu_id)
{
	assert(from_fwk != NULL);

	(void)vcpu_id;

	if (!vm_id_is_current_world(receiver_locked.vm->id) &&
	    (flags & FFA_NOTIFICATION_FLAG_BITMAP_HYP) != 0U) {
		dlog_error(
			"Notification get flag from hypervisor in call to SPMC "
			"MBZ.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	*from_fwk = vm_notifications_framework_get_pending(receiver_locked);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

static void plat_ffa_send_schedule_receiver_interrupt(struct cpu *cpu)
{
	dlog_verbose("Setting Schedule Receiver SGI %u on core: %zu\n",
		     HF_SCHEDULE_RECEIVER_INTID, cpu_index(cpu));

	plat_interrupts_send_sgi(HF_SCHEDULE_RECEIVER_INTID, cpu, false);
}

static void ffa_notifications_sri_set_delayed_internal(struct cpu *cpu,
						       bool delayed)
{
	assert(cpu != NULL);
	cpu->is_sri_delayed = delayed;
}

void ffa_notifications_sri_set_delayed(struct cpu *cpu)
{
	ffa_notifications_sri_set_delayed_internal(cpu, true);
}

static bool plat_ffa_is_sri_delayed(struct cpu *cpu)
{
	assert(cpu != NULL);
	return cpu->is_sri_delayed;
}

void ffa_notifications_sri_trigger_if_delayed(struct cpu *cpu)
{
	assert(cpu != NULL);

	if (plat_ffa_is_sri_delayed(cpu)) {
		plat_ffa_send_schedule_receiver_interrupt(cpu);
		ffa_notifications_sri_set_delayed_internal(cpu, false);
	}
}

void ffa_notifications_sri_trigger_not_delayed(struct cpu *cpu)
{
	/*
	 * If flag to delay SRI isn't set, trigger SRI such that the
	 * receiver scheduler is aware there are pending notifications.
	 */
	plat_ffa_send_schedule_receiver_interrupt(cpu);
	ffa_notifications_sri_set_delayed_internal(cpu, false);
}

void ffa_notifications_sri_init(struct cpu *cpu)
{
	/* Configure as Non Secure SGI. */
	struct interrupt_descriptor sri_desc = {
		.interrupt_id = HF_SCHEDULE_RECEIVER_INTID,
		.type = INT_DESC_TYPE_SGI,
		.sec_state = INT_DESC_SEC_STATE_NS,
		.priority = SRI_PRIORITY,
		.valid = true,
	};

	/* TODO: when supported, make the interrupt driver use cpu structure. */
	(void)cpu;

	plat_interrupts_configure_interrupt(sri_desc);
}
