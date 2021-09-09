/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/sve.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "smc.h"

/** Other world SVE context (accessed from other_world_loop). */
struct sve_context_t sve_context[MAX_CPUS];

/**
 * The SPMC needs to keep track of some information about NWd VMs.
 * For the time being, only the notifications state structures.
 * Allocation and deallocation of a slot in 'nwd_vms' to and from a given VM
 * will happen upon calls to FFA_NOTIFICATION_BITMAP_CREATE and
 * FFA_NOTIFICATION_BITMAP_DESTROY.
 */
static struct vm nwd_vms[MAX_VMS];

/**
 * All accesses to `nwd_vms` needs to be guarded by this lock.
 */
static struct spinlock nwd_vms_lock_instance = SPINLOCK_INIT;

/**
 * Encapsulates the set of share states while the `nwd_vms_lock_instance` is
 * held.
 */
struct nwd_vms_locked {
	struct vm *nwd_vms;
};

const uint32_t nwd_vms_size = ARRAY_SIZE(nwd_vms);

/** Locks the normal world vms guarding lock. */
static struct nwd_vms_locked nwd_vms_lock(void)
{
	sl_lock(&nwd_vms_lock_instance);

	return (struct nwd_vms_locked){.nwd_vms = nwd_vms};
}

/** Unlocks the normal world vms guarding lock. */
static void nwd_vms_unlock(struct nwd_vms_locked *vms)
{
	CHECK(vms->nwd_vms == nwd_vms);
	vms->nwd_vms = NULL;
	sl_unlock(&nwd_vms_lock_instance);
}

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (SPMC)\n");
}

/** Returns information on features specific to the SWd. */
struct ffa_value plat_ffa_features(uint32_t function_id)
{
	(void)function_id;
	/* There are no features only supported in the SWd */
	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_spmc_id_get(void)
{
	/*
	 * Since we are running in the SPMC use FFA_ID_GET to fetch our
	 * ID from the SPMD.
	 */
	return smc_ffa_call((struct ffa_value){.func = FFA_ID_GET_32});
}

static void plat_ffa_vm_init(void)
{
	/* Init NWd VMs structures for use of Notifications interfaces. */
	for (uint32_t i = 0; i < nwd_vms_size; i++) {
		/*
		 * A slot in 'nwd_vms' is considered available if its id
		 * is HF_INVALID_VM_ID.
		 */
		nwd_vms[i].id = HF_INVALID_VM_ID;
		vm_notifications_init_bindings(
			&nwd_vms[i].notifications.from_sp);
	}
}

void plat_ffa_init(bool tee_enabled)
{
	(void)tee_enabled;

	arch_ffa_init();
	plat_ffa_vm_init();
}

bool plat_ffa_run_forward(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	(void)vm_id;
	(void)vcpu_idx;
	(void)ret;

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
	 * The normal world can send direct message requests
	 * via the Hypervisor to any SP. Currently SPs can only send
	 * direct messages to each other and not to the NWd.
	 */
	return sender_vm_id != receiver_vm_id &&
	       vm_id_is_current_world(receiver_vm_id) &&
	       (sender_vm_id == current_vm_id ||
		(current_vm_id == HF_HYPERVISOR_VM_ID &&
		 !vm_id_is_current_world(sender_vm_id)));
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
	 * Direct message responses emitted from a SP target either the NWd
	 * or another SP.
	 */
	return sender_vm_id != receiver_vm_id &&
	       sender_vm_id == current_vm_id &&
	       vm_id_is_current_world(sender_vm_id);
}

bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
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

bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id)
{
	/**
	 * Create/Destroy interfaces to be called by the hypervisor, into the
	 * SPMC.
	 */
	return current->vm->id == HF_HYPERVISOR_VM_ID &&
	       !vm_id_is_current_world(vm_id);
}

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/**
	 * SPMC:
	 * - If bind call from SP, receiver's ID must be same as current VM ID.
	 * - If bind call from NWd, current VM ID must be same as Hypervisor ID,
	 * receiver's ID must be from NWd, and sender's ID from SWd.
	 */
	return sender_id != receiver_id &&
	       (current_vm_id == receiver_id ||
		(current_vm_id == HF_HYPERVISOR_VM_ID &&
		 !vm_id_is_current_world(receiver_id) &&
		 vm_id_is_current_world(sender_id)));
}

bool plat_ffa_notifications_update_bindings_forward(
	ffa_vm_id_t receiver_id, ffa_vm_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret)
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

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/*
	 * SPMC:
	 * - If set call from SP, sender's ID must be the same as current.
	 * - If set call from NWd, current VM ID must be same as Hypervisor ID,
	 * and receiver must be an SP.
	 */
	return sender_id != receiver_id &&
	       (sender_id == current_vm_id ||
		(current_vm_id == HF_HYPERVISOR_VM_ID &&
		 !vm_id_is_current_world(sender_id) &&
		 vm_id_is_current_world(receiver_id)));
}

bool plat_ffa_notification_set_forward(ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id,
				       uint32_t flags,
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

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id)
{
	ffa_vm_id_t current_vm_id = current->vm->id;

	/*
	 * SPMC:
	 * - An SP can ask for its notifications, or the hypervisor can get
	 *  notifications target to a VM.
	 */
	return (current_vm_id == receiver_id) ||
	       (current_vm_id == HF_HYPERVISOR_VM_ID &&
		!vm_id_is_current_world(receiver_id));
}

ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index)
{
	return (index & ~FFA_MEMORY_HANDLE_ALLOCATOR_MASK) |
	       FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;
}

bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle)
{
	return (handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	       FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t vm_id, const struct vm *target)
{
	ffa_partition_properties_t result = target->messaging_method;
	/*
	 * SPs support full direct messaging communication with other SPs,
	 * and are allowed to only receive direct requests from the other world.
	 * SPs cannot send direct requests to the other world.
	 */
	if (vm_id_is_current_world(vm_id)) {
		return result & (FFA_PARTITION_DIRECT_REQ_RECV |
				 FFA_PARTITION_DIRECT_REQ_SEND);
	}
	return result & FFA_PARTITION_DIRECT_REQ_RECV;
}

bool plat_ffa_vm_managed_exit_supported(struct vm *vm)
{
	return vm->managed_exit;
}

/** Allocates a NWd VM structure to the VM of given ID. */
static void plat_ffa_vm_create(struct nwd_vms_locked nwd_vms_locked,
			       struct vm_locked to_create_locked,
			       ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	CHECK(nwd_vms_locked.nwd_vms != NULL);
	CHECK(to_create_locked.vm != NULL &&
	      to_create_locked.vm->id == HF_INVALID_VM_ID);

	to_create_locked.vm->id = vm_id;
	to_create_locked.vm->vcpu_count = vcpu_count;
	to_create_locked.vm->notifications.enabled = true;
}

static void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked)
{
	to_destroy_locked.vm->id = HF_INVALID_VM_ID;
	to_destroy_locked.vm->vcpu_count = 0U;
	vm_notifications_init_bindings(
		&to_destroy_locked.vm->notifications.from_sp);
	to_destroy_locked.vm->notifications.enabled = false;
}

static struct vm_locked plat_ffa_nwd_vm_find_locked(
	struct nwd_vms_locked nwd_vms_locked, ffa_vm_id_t vm_id)
{
	CHECK(nwd_vms_locked.nwd_vms != NULL);

	for (unsigned int i = 0U; i < nwd_vms_size; i++) {
		if (nwd_vms[i].id == vm_id) {
			return vm_lock(&nwd_vms[i]);
		}
	}

	return (struct vm_locked){.vm = NULL};
}

struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id)
{
	struct vm_locked to_ret_locked;

	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	struct nwd_vms_locked nwd_vms_locked = nwd_vms_lock();

	to_ret_locked = plat_ffa_nwd_vm_find_locked(nwd_vms_locked, vm_id);

	nwd_vms_unlock(&nwd_vms_locked);

	return to_ret_locked;
}

struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vm_locked vm_locked;
	const char *error_string = "Notification bitmap already created.";
	struct nwd_vms_locked nwd_vms_locked = nwd_vms_lock();

	if (vm_id == HF_OTHER_WORLD_ID) {
		/*
		 * If the provided VM ID regards to the Hypervisor, represented
		 * by the other world VM with ID HF_OTHER_WORLD_ID, check if the
		 * notifications have been enabled.
		 */

		vm_locked = vm_find_locked(vm_id);

		CHECK(vm_locked.vm != NULL);

		/* Call has been used for the other world vm already */
		if (vm_locked.vm->notifications.enabled != false) {
			dlog_error("%s\n", error_string);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		/* Enable notifications for `other_world_vm`. */
		vm_locked.vm->notifications.enabled = true;

	} else {
		/* Else should regard with NWd VM ID. */

		/* If vm already exists bitmap has been created as well. */
		vm_locked = plat_ffa_nwd_vm_find_locked(nwd_vms_locked, vm_id);
		if (vm_locked.vm != NULL) {
			dlog_error("%s\n", error_string);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		/* Get first empty slot in `nwd_vms` to create VM. */
		vm_locked = plat_ffa_nwd_vm_find_locked(nwd_vms_locked,
							HF_INVALID_VM_ID);

		/*
		 * If received NULL, means there are no slots in `nwd_vms` for
		 * VM creation.
		 */
		if (vm_locked.vm == NULL) {
			dlog_error("No memory to create.\n");
			ret = ffa_error(FFA_NO_MEMORY);
			goto out;
		}

		plat_ffa_vm_create(nwd_vms_locked, vm_locked, vm_id,
				   vcpu_count);
	}

out:
	vm_unlock(&vm_locked);
	nwd_vms_unlock(&nwd_vms_locked);

	return ret;
}

bool plat_ffa_notifications_bitmap_create_call(ffa_vm_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return false;
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	struct vm_locked to_destroy_locked;
	const char *error_not_created_string = "Bitmap not created for vm:";

	if (vm_id == HF_OTHER_WORLD_ID) {
		/*
		 * Bitmap is part of `other_world_vm`, destroy will reset
		 * bindings and will disable notifications.
		 */

		to_destroy_locked = vm_find_locked(vm_id);

		CHECK(to_destroy_locked.vm != NULL);

		if (to_destroy_locked.vm->notifications.enabled == false) {
			dlog_error("%s %u\n", error_not_created_string, vm_id);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		/* Check if there is any notification pending. */
		if (vm_are_notifications_pending(to_destroy_locked, false,
						 ~0x0U)) {
			dlog_verbose("VM has notifications pending.\n");
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		to_destroy_locked.vm->notifications.enabled = false;
		vm_notifications_init_bindings(
			&to_destroy_locked.vm->notifications.from_sp);
	} else {
		to_destroy_locked = plat_ffa_vm_find_locked(vm_id);

		/* If VM doesn't exist, bitmap hasn't been created. */
		if (to_destroy_locked.vm == NULL) {
			dlog_verbose("%s: %u.\n", error_not_created_string,
				     vm_id);
			return ffa_error(FFA_DENIED);
		}

		/* Check if there is any notification pending. */
		if (vm_are_notifications_pending(to_destroy_locked, false,
						 ~0x0U)) {
			dlog_verbose("VM has notifications pending.\n");
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		plat_ffa_vm_destroy(to_destroy_locked);
	}
out:
	vm_unlock(&to_destroy_locked);
	return ret;
}

bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id)
{
	return !vm_id_is_current_world(vm_id);
}

bool plat_ffa_notifications_get_from_sp(struct vm_locked receiver_locked,
					ffa_vcpu_index_t vcpu_id,
					ffa_notifications_bitmap_t *from_sp,
					struct ffa_value *ret)
{
	(void)ret;

	*from_sp = vm_notifications_get_pending_and_clear(receiver_locked,
							  false, vcpu_id);

	return true;
}

bool plat_ffa_vm_notifications_info_get(uint16_t *ids, uint32_t *ids_count,
					uint32_t *lists_sizes,
					uint32_t *lists_count,
					const uint32_t ids_count_max)
{
	enum notifications_info_get_state info_get_state = INIT;
	struct nwd_vms_locked nwd_vms_locked = nwd_vms_lock();
	struct vm_locked other_world_locked = vm_find_locked(HF_OTHER_WORLD_ID);

	CHECK(other_world_locked.vm != NULL);

	vm_notifications_info_get_pending(other_world_locked, false, ids,
					  ids_count, lists_sizes, lists_count,
					  ids_count_max, &info_get_state);

	if (info_get_state == FULL) {
		goto out;
	}

	vm_unlock(&other_world_locked);

	for (unsigned int i = 0; i < nwd_vms_size; i++) {
		info_get_state = INIT;

		if (nwd_vms[i].id != HF_INVALID_VM_ID) {
			struct vm_locked vm_locked = vm_lock(&nwd_vms[i]);

			vm_notifications_info_get_pending(
				vm_locked, false, ids, ids_count, lists_sizes,
				lists_count, ids_count_max, &info_get_state);

			if (info_get_state == FULL) {
				goto out;
			}

			vm_unlock(&vm_locked);
		}
	}
out:
	nwd_vms_unlock(&nwd_vms_locked);

	return info_get_state == FULL;
}
