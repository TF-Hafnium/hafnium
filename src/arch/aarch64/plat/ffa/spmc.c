/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/mmu.h"
#include "hf/arch/other_world.h"
#include "hf/arch/plat/ffa.h"
#include "hf/arch/sve.h"

#include "hf/api.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/interrupt_desc.h"
#include "hf/plat/interrupts.h"
#include "hf/std.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

#include "msr.h"
#include "smc.h"
#include "sysregs.h"

/** Interrupt priority for the Schedule Receiver Interrupt. */
#define SRI_PRIORITY 0x10U

/** Encapsulates `sri_state` while the `sri_state_lock` is held. */
struct sri_state_locked {
	enum plat_ffa_sri_state *sri_state;
};

/** To globally keep track of the SRI handling. */
static enum plat_ffa_sri_state sri_state = HANDLED;

/** Lock to guard access to `sri_state`. */
static struct spinlock sri_state_lock_instance = SPINLOCK_INIT;

/** Locks `sri_state` guarding lock. */
static struct sri_state_locked sri_state_lock(void)
{
	sl_lock(&sri_state_lock_instance);

	return (struct sri_state_locked){.sri_state = &sri_state};
}

/** Unlocks `sri_state` guarding lock. */
void sri_state_unlock(struct sri_state_locked sri_state_locked)
{
	assert(sri_state_locked.sri_state == &sri_state);
	sri_state_locked.sri_state = NULL;
	sl_unlock(&sri_state_lock_instance);
}

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
struct ffa_value plat_ffa_features(uint32_t function_feature_id)
{
	struct ffa_value ret;

	switch (function_feature_id) {
#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
	case FFA_FEATURE_MEI:
		ret = api_ffa_feature_success(HF_MANAGED_EXIT_INTID);
		break;
#endif
	default:
		ret = ffa_error(FFA_NOT_SUPPORTED);
		break;
	}

	/* There are no features only supported in the SWd */
	return ret;
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
 * Check that the receiver supports receipt of direct requests, and that the
 * sender supports sending direct messaging requests, in accordance to their
 * respective configurations at the partition's FF-A manifest.
 */
bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm)
{
	if (!vm_supports_messaging_method(sender_vm,
					  FFA_PARTITION_DIRECT_REQ_SEND)) {
		dlog_verbose("Sender can't send direct message requests.\n");
		return false;
	}

	if (!vm_supports_messaging_method(receiver_vm,
					  FFA_PARTITION_DIRECT_REQ_RECV)) {
		dlog_verbose(
			"Receiver can't receive direct message requests.\n");
		return false;
	}

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

void plat_ffa_notification_info_get_forward(  // NOLINTNEXTLINE
	uint16_t *ids, uint32_t *ids_count,   // NOLINTNEXTLINE
	uint32_t *lists_sizes, uint32_t *lists_count,
	const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;
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
	assert(nwd_vms_locked.nwd_vms != NULL);

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

	return true;
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

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current)
{
	/* FFA_MEM_PERM_SET/GET is only valid before SPs are initialized */
	return has_vhe_support() && (current->vm->initialized == false);
}

bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current)
{
	/* FFA_MEM_PERM_SET/GET is only valid before SPs are initialized */
	return has_vhe_support() && (current->vm->initialized == false);
}

/**
 * Check if current VM can resume target VM using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu *current, ffa_vm_id_t target_vm_id,
			 ffa_vcpu_index_t vcpu_idx, struct ffa_value *run_ret,
			 struct vcpu **next)
{
	(void)next;
	/*
	 * Under the Partition runtime model specified in FF-A v1.1-Beta0 spec,
	 * SP can invoke FFA_RUN to resume target SP.
	 */
	struct vcpu *target_vcpu;
	bool ret = true;
	struct vm *vm;

	vm = vm_find(target_vm_id);
	if (vm == NULL) {
		return false;
	}

	if (vm->vcpu_count > 1 && vcpu_idx != cpu_index(current->cpu)) {
		dlog_verbose("vcpu_idx (%d) != pcpu index (%d)\n", vcpu_idx,
			     cpu_index(current->cpu));
		return false;
	}

	target_vcpu = api_ffa_get_vm_vcpu(vm, current);

	/* Lock both vCPUs at once. */
	vcpu_lock_both(current, target_vcpu);

	/* Only the primary VM can turn ON a vCPU that is currently OFF. */
	if (current->vm->id != HF_PRIMARY_VM_ID &&
	    target_vcpu->state == VCPU_STATE_OFF) {
		run_ret->arg2 = FFA_DENIED;
		ret = false;
		goto out;
	}

	/* A SP cannot invoke FFA_RUN to resume a normal world VM. */
	if (!vm_id_is_current_world(target_vm_id)) {
		run_ret->arg2 = FFA_DENIED;
		ret = false;
		goto out;
	}

	if ((current->vm->id & HF_VM_ID_WORLD_MASK) != 0) {
		/*
		 * Refer FF-A v1.1 Beta0 section 8.3.
		 * SPMC treats the first invocation of FFA_RUN as interrupt
		 * completion signal when interrupt handling is ongoing.
		 * TODO: Current design limitation. We expect the current SP
		 * to resume the vCPU of preempted SP through this FFA_RUN.
		 */
		if (current->processing_secure_interrupt) {
			/*
			 * Refer FF-A v1.1 Beta0 section 8.3 Rule 2. FFA_RUN
			 * ABI is used for secure interrupt signal completion by
			 * SP if it was in BLOCKED state.
			 */
			CHECK(current->state == VCPU_STATE_BLOCKED);

			CHECK(target_vcpu == current->preempted_vcpu);

			/* Unmask interrupts. */
			plat_interrupts_set_priority_mask(0xff);

			/*
			 * Clear fields corresponding to secure interrupt
			 * handling.
			 */
			current->processing_secure_interrupt = false;
			current->secure_interrupt_deactivated = false;
			current->preempted_vcpu = NULL;
			current->current_sec_interrupt_id = 0;
		}
	}
out:
	sl_unlock(&target_vcpu->lock);
	sl_unlock(&current->lock);
	return ret;
}

/**
 * Drops the current interrupt priority and deactivate the given interrupt ID
 * for the calling vCPU.
 *
 * Returns 0 on success, or -1 otherwise.
 */
int64_t plat_ffa_interrupt_deactivate(uint32_t pint_id, uint32_t vint_id,
				      struct vcpu *current)
{
	if (vint_id >= HF_NUM_INTIDS) {
		return -1;
	}

	/*
	 * Current implementation maps virtual interrupt to physical interrupt.
	 */
	if (pint_id != vint_id) {
		return -1;
	}

	/*
	 * Deny the de-activation request if not currently processing a
	 * secure interrupt. panic() is not appropriate as it could be
	 * abused by a rogue SP to create Denial-of-service.
	 */
	if (!current->processing_secure_interrupt) {
		dlog_error("Cannot deactivate secure interrupt: %d\n", pint_id);
		return -1;
	}

	/*
	 * A malicious SP could de-activate an interrupt that does not belong to
	 * it. Return error to indicate failure.
	 */
	if (current->current_sec_interrupt_id != pint_id) {
		return -1;
	}

	if (!current->secure_interrupt_deactivated) {
		plat_interrupts_end_of_interrupt(pint_id);
		current->secure_interrupt_deactivated = true;
	}

	return 0;
}

static struct vcpu *plat_ffa_find_target_vcpu(struct vcpu *current,
					      uint32_t interrupt_id)
{
	bool target_vm_found = false;
	struct vm *vm;
	struct vcpu *target_vcpu;
	struct interrupt_descriptor int_desc;

	/*
	 * Find which VM/SP owns this interrupt. We then find the corresponding
	 * vCPU context for this CPU.
	 */
	for (ffa_vm_count_t index = 0; index < vm_get_count(); ++index) {
		vm = vm_find_index(index);

		for (uint32_t j = 0; j < HF_NUM_INTIDS; j++) {
			int_desc = vm->interrupt_desc[j];

			/* Interrupt descriptors are populated contiguously. */
			if (!int_desc.valid) {
				break;
			}
			if (int_desc.interrupt_id == interrupt_id) {
				target_vm_found = true;
				goto out;
			}
		}
	}
out:
	CHECK(target_vm_found);

	target_vcpu = api_ffa_get_vm_vcpu(vm, current);

	/* The target vCPU for a secure interrupt cannot be NULL. */
	CHECK(target_vcpu != NULL);

	return target_vcpu;
}

/**
 * TODO: As of now, we did not implement support for checking legal state
 * transitions defined under the partition runtime models defined in the
 * FF-A v1.1-Beta0 spec.
 * Moreover, support for scheduling models has not been implemented. However,
 * the current implementation loosely maps to the following valid actions for
 * a S-EL1 Partition as described in Table 8.14 of FF-A v1.1 Beta0 spec with
 * the exception that Other S-Int are unconditionally queued during secure
 * interrupt handling.
 * Refer Table 8.5 for detailed description of actions.

 Runtime Model		NS-Int			Self S-Int	Other S-Int
 --------------------------------------------------------------------------
 Message Processing	Signalable with ME	Signalable	Signalable
 Interrupt Handling	Queued			Queued		Queued
 --------------------------------------------------------------------------
 */
static struct vcpu_locked plat_ffa_secure_interrupt_prepare(
	struct vcpu *current, uint32_t *int_id)
{
	struct vcpu_locked current_vcpu_locked;
	struct vcpu_locked target_vcpu_locked;
	struct vcpu *target_vcpu;
	uint32_t id;

	/* Find pending interrupt id. This also activates the interrupt. */
	id = plat_interrupts_get_pending_interrupt_id();

	target_vcpu = plat_ffa_find_target_vcpu(current, id);

	/* Update the state of current vCPU. */
	current_vcpu_locked = vcpu_lock(current);
	current->state = VCPU_STATE_PREEMPTED;
	vcpu_unlock(&current_vcpu_locked);

	/*
	 * TODO: Temporarily mask all interrupts to disallow high priority
	 * interrupts from pre-empting current interrupt processing.
	 */
	plat_interrupts_set_priority_mask(0x0);

	target_vcpu_locked = vcpu_lock(target_vcpu);

	/*
	 * TODO: Design limitation. Current implementation does not support
	 * handling a secure interrupt while currently handling a secure
	 * interrupt. Moreover, we cannot queue more than one virtual interrupt
	 * at a time.
	 */
	CHECK(!target_vcpu->processing_secure_interrupt);
	CHECK(vcpu_interrupt_irq_count_get(target_vcpu_locked) == 0);

	/* Inject this interrupt as a vIRQ to the target SP context. */
	/* TODO: check api_interrupt_inject_locked return value. */
	(void)api_interrupt_inject_locked(target_vcpu_locked, id, current,
					  NULL);
	*int_id = id;
	return target_vcpu_locked;
}

static void plat_ffa_signal_secure_interrupt(
	struct vcpu_locked target_vcpu_locked, uint32_t id, struct vcpu **next)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct ffa_value args = {
		.func = (uint32_t)FFA_INTERRUPT_32,
	};

	/*
	 * Switch to target vCPU responsible for this interrupt. If target
	 * vCPU cannot be resumed, SPMC resumes current vCPU.
	 */
	*next = target_vcpu;

	switch (target_vcpu->state) {
	case VCPU_STATE_WAITING:
		/* FF-A v1.1 Beta0 section 7.4 bullet 1 and Table 8.2 case 1. */
		args.arg1 = id;
		break;
	case VCPU_STATE_BLOCKED:
		break;
	case VCPU_STATE_PREEMPTED:
		/*
		 * We do not resume a target vCPU that has been already
		 * pre-empted by an interrupt or waiting for an
		 * interrupt(WFI). We only pend the vIRQ for target SP
		 * and continue to resume current vCPU.
		 */
		*next = NULL;

		/*
		 * De-activate the interrupt. If not, it could trigger again
		 * after resuming current vCPU.
		 */
		plat_interrupts_end_of_interrupt(id);
		target_vcpu->secure_interrupt_deactivated = true;
		return;
	case VCPU_STATE_BLOCKED_INTERRUPT:
		/* WFI is no-op for SP. Fall through*/
	default:
		/*
		 * vCPU of Target SP cannot be in RUNNING/OFF/ABORTED
		 * state if it has to handle secure interrupt.
		 */
		panic("Secure interrupt cannot be signaled to target "
		      "SP\n");
		break;
	}

	CHECK((*next)->regs_available);
	arch_regs_set_retval(&((*next)->regs), args);

	/*
	 * Strictly speaking, we are about to resume target vCPU which means it
	 * should move to RUNNING state. But, we do not modify the state as per
	 * rules defined in section 7.4 of FF-A v1.1 Beta0 spec. This is because
	 * we associate the state of vCPU with the mechanism used for interrupt
	 * completion.
	 */

	/* Mark the registers as unavailable now. */
	(*next)->regs_available = false;
}

/**
 * Obtain the Self S-Int/Other S-Int physical interrupt ID from the interrupt
 * controller and inject the corresponding virtual interrupt to the target vCPU
 * for handling.
 */
void plat_ffa_secure_interrupt(struct vcpu *current, struct vcpu **next)
{
	struct vcpu_locked target_vcpu_locked;
	uint32_t id;

	/* Secure interrupt triggered while execution is in SWD. */
	CHECK((current->vm->id & HF_VM_ID_WORLD_MASK) != 0);
	target_vcpu_locked = plat_ffa_secure_interrupt_prepare(current, &id);

	if (current == target_vcpu_locked.vcpu) {
		/*
		 * A scenario where target vCPU is the current vCPU in secure
		 * world.
		 */
		dlog_verbose("Resume current vCPU\n");
		*next = NULL;

		/* We have already locked vCPU. */
		current->state = VCPU_STATE_RUNNING;

		/*
		 * In scenario where target vCPU is the current vCPU in
		 * secure world, there is no vCPU to resume when target
		 * vCPU exits after secure interrupt completion.
		 */
		target_vcpu_locked.vcpu->preempted_vcpu = NULL;
	} else {
		plat_ffa_signal_secure_interrupt(target_vcpu_locked, id, next);
		/*
		 * In the scenario where target SP cannot be resumed for
		 * processing interrupt, resume the current vCPU.
		 */
		if (*next == NULL) {
			target_vcpu_locked.vcpu->preempted_vcpu = NULL;
		} else {
			target_vcpu_locked.vcpu->preempted_vcpu = current;
		}
	}

	target_vcpu_locked.vcpu->processing_secure_interrupt = true;
	target_vcpu_locked.vcpu->current_sec_interrupt_id = id;
	vcpu_unlock(&target_vcpu_locked);
}

/**
 * Secure interrupts in the normal world are trapped to EL3. SPMD then routes
 * the interrupt to SPMC through FFA_INTERRUPT_32 ABI synchronously using eret
 * conduit.
 */
struct ffa_value plat_ffa_delegate_ffa_interrupt(struct vcpu *current,
						 struct vcpu **next)
{
	struct ffa_value ffa_ret = ffa_error(FFA_NOT_SUPPORTED);
	uint32_t id;
	struct vcpu_locked target_vcpu_locked;

	/*
	 * A malicious SP could invoke a HVC call with FFA_INTERRUPT_32 as
	 * the function argument. Return error to avoid DoS.
	 */
	if (current->vm->id != HF_OTHER_WORLD_ID) {
		return ffa_error(FFA_DENIED);
	}

	target_vcpu_locked = plat_ffa_secure_interrupt_prepare(current, &id);
	plat_ffa_signal_secure_interrupt(target_vcpu_locked, id, next);

	/*
	 * current refers to other world. target must be a vCPU in the secure
	 * world.
	 */
	CHECK(*next != current);

	target_vcpu_locked.vcpu->processing_secure_interrupt = true;
	target_vcpu_locked.vcpu->current_sec_interrupt_id = id;

	/*
	 * next==NULL represents a scenario where SPMC cannot resume target SP.
	 * Resume normal world using FFA_NORMAL_WORLD_RESUME.
	 */
	if (*next == NULL) {
		ffa_ret = (struct ffa_value){.func = FFA_NORMAL_WORLD_RESUME};
		target_vcpu_locked.vcpu->preempted_vcpu = NULL;
	} else {
		target_vcpu_locked.vcpu->preempted_vcpu = current;
	}
	vcpu_unlock(&target_vcpu_locked);

	return ffa_ret;
}

/**
 * Switches the physical CPU back to the corresponding vCPU of the normal world.
 *
 * The current vCPU has finished handling the secure interrupt. Resume the
 * execution in the normal world by invoking the FFA_NORMAL_WORLD_RESUME ABI
 * in SPMC that is processed by SPMD to make the world context switch. Refer
 * FF-A v1.1 Beta0 section 14.4.
 */
struct ffa_value plat_ffa_normal_world_resume(struct vcpu *current,
					      struct vcpu **next)
{
	struct ffa_value ffa_ret = (struct ffa_value){.func = FFA_MSG_WAIT_32};
	struct ffa_value other_world_ret =
		(struct ffa_value){.func = FFA_NORMAL_WORLD_RESUME};
	struct vcpu_locked current_locked;

	current_locked = vcpu_lock(current);

	/* Indicate that secure interrupt processing is complete. */
	current->processing_secure_interrupt = false;

	/* Reset the flag. */
	current->secure_interrupt_deactivated = false;

	/* Clear fields corresponding to secure interrupt handling. */
	current->preempted_vcpu = NULL;
	current->current_sec_interrupt_id = 0;
	vcpu_unlock(&current_locked);

	/* Unmask interrupts. */
	plat_interrupts_set_priority_mask(0xff);

	*next = api_switch_to_other_world(current, other_world_ret,
					  VCPU_STATE_WAITING);

	/* The next vCPU to be run cannot be null. */
	CHECK(*next != NULL);

	return ffa_ret;
}

/**
 * A SP in running state could have been pre-empted by a secure interrupt. SPM
 * would switch the execution to the vCPU of target SP responsible for interupt
 * handling. Upon completion of interrupt handling, vCPU performs interrupt
 * signal completion through FFA_MSG_WAIT ABI (provided it was in waiting state
 * when interrupt was signaled).
 *
 * SPM then resumes the original SP that was initially pre-empted.
 */
struct ffa_value plat_ffa_preempted_vcpu_resume(struct vcpu *current,
						struct vcpu **next)
{
	struct ffa_value ffa_ret = (struct ffa_value){.func = FFA_MSG_WAIT_32};
	struct vcpu *target_vcpu;

	CHECK(current->preempted_vcpu != NULL);
	CHECK(current->preempted_vcpu->state == VCPU_STATE_PREEMPTED);

	target_vcpu = current->preempted_vcpu;

	/* Lock both vCPUs at once. */
	vcpu_lock_both(current, target_vcpu);

	/* Indicate that secure interrupt processing is complete. */
	current->processing_secure_interrupt = false;

	/* Reset the flag. */
	current->secure_interrupt_deactivated = false;

	/* Clear fields corresponding to secure interrupt handling. */
	current->preempted_vcpu = NULL;
	current->current_sec_interrupt_id = 0;

	target_vcpu->state = VCPU_STATE_RUNNING;

	/* Mark the registers as unavailable now. */
	target_vcpu->regs_available = false;
	sl_unlock(&target_vcpu->lock);
	sl_unlock(&current->lock);

	/* Unmask interrupts. */
	plat_interrupts_set_priority_mask(0xff);

	/* The pre-empted vCPU should be run. */
	*next = target_vcpu;

	return ffa_ret;
}

static void sri_state_set(struct sri_state_locked sri_state_locked,
			  enum plat_ffa_sri_state state)
{
	assert(sri_state_locked.sri_state != NULL &&
	       sri_state_locked.sri_state == &sri_state);

	switch (*(sri_state_locked.sri_state)) {
	case TRIGGERED:
		/*
		 * If flag to delay SRI is set, and SRI hasn't been
		 * triggered state to delayed such that it is triggered
		 * at context switch to the receiver scheduler.
		 */
		if (state == DELAYED) {
			break;
		}
	case HANDLED:
	case DELAYED:
		*(sri_state_locked.sri_state) = state;
		break;
	default:
		panic("Invalid SRI state\n");
	}
}

void plat_ffa_sri_state_set(enum plat_ffa_sri_state state)
{
	struct sri_state_locked sri_state_locked = sri_state_lock();

	sri_state_set(sri_state_locked, state);
	sri_state_unlock(sri_state_locked);
}

static void plat_ffa_send_schedule_receiver_interrupt(struct cpu *cpu)
{
	dlog_verbose("Setting Schedule Receiver SGI %d on core: %d\n",
		     HF_SCHEDULE_RECEIVER_INTID, cpu_index(cpu));

	plat_interrupts_send_sgi(HF_SCHEDULE_RECEIVER_INTID, false,
				 (1 << cpu_index(cpu)), false);
}

void plat_ffa_sri_trigger_if_delayed(struct cpu *cpu)
{
	struct sri_state_locked sri_state_locked = sri_state_lock();

	if (*(sri_state_locked.sri_state) == DELAYED) {
		dlog_verbose("Triggering delayed SRI!\n");
		plat_ffa_send_schedule_receiver_interrupt(cpu);
		sri_state_set(sri_state_locked, TRIGGERED);
	}

	sri_state_unlock(sri_state_locked);
}

void plat_ffa_sri_trigger_not_delayed(struct cpu *cpu)
{
	struct sri_state_locked sri_state_locked = sri_state_lock();

	if (*(sri_state_locked.sri_state) == HANDLED) {
		/*
		 * If flag to delay SRI isn't set, trigger SRI such that the
		 * receiver scheduler is aware there are pending notifications.
		 */
		dlog_verbose("Triggering not delayed SRI!\n");
		plat_ffa_send_schedule_receiver_interrupt(cpu);
		sri_state_set(sri_state_locked, TRIGGERED);
	}

	sri_state_unlock(sri_state_locked);
}

void plat_ffa_sri_init(struct cpu *cpu)
{
	struct interrupt_descriptor sri_desc;

	/* TODO: when supported, make the interrupt driver use cpu structure. */
	(void)cpu;

	interrupt_desc_set_id(&sri_desc, HF_SCHEDULE_RECEIVER_INTID);
	interrupt_desc_set_priority(&sri_desc, SRI_PRIORITY);
	interrupt_desc_set_valid(&sri_desc, true);

	/* Configure Interrupt as Non-Secure. */
	interrupt_desc_set_type_config_sec_state(&sri_desc,
						 INT_DESC_TYPE_SGI << 2);

	plat_interrupts_configure_interrupt(sri_desc);
}

void plat_ffa_inject_notification_pending_interrupt_context_switch(
	struct vcpu *next, struct vcpu *current)
{
	CHECK(current != NULL);
	/*
	 * If NWd is giving CPU cycles to SP, check if it is necessary
	 * to inject VI Notifications Pending Interrupt.
	 */
	if (current->vm->id == HF_OTHER_WORLD_ID && next != NULL &&
	    vm_id_is_current_world(next->vm->id)) {
		struct vm_locked target_vm_locked =
			vm_find_locked(next->vm->id);
		/*
		 * If per-vCPU notifications are pending, NPI has been
		 * injected at FFA_NOTIFICATION_SET handling in the
		 * targeted vCPU. If next SP has pending global
		 * notifications, only inject if there are no pending
		 * per-vCPU notifications, to avoid injecting spurious
		 * interrupt.
		 */
		if (!vm_are_per_vcpu_notifications_pending(target_vm_locked,
							   vcpu_index(next)) &&
		    vm_are_global_notifications_pending(target_vm_locked)) {
			struct vcpu_locked next_locked = vcpu_lock(next);

			api_interrupt_inject_locked(
				next_locked, HF_NOTIFICATION_PENDING_INTID,
				current, NULL);

			vcpu_unlock(&next_locked);
		}
		vm_unlock(&target_vm_locked);
	}
}

/** Forward helper for FFA_PARTITION_INFO_GET. */
void plat_ffa_partition_info_get_forward(  // NOLINTNEXTLINE
	const struct ffa_uuid *uuid,	   // NOLINTNEXTLINE
	const uint32_t flags,		   // NOLINTNEXTLINE
	struct ffa_partition_info *partitions, ffa_vm_count_t *ret_count)
{
	/* The SPMC does not forward FFA_PARTITION_INFO_GET. */

	(void)uuid;
	(void)flags;
	(void)partitions;
	(void)ret_count;
}

void plat_ffa_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
				       paddr_t fdt_addr,
				       size_t fdt_allocated_size,
				       const struct manifest_vm *manifest_vm,
				       struct mpool *ppool)
{
	(void)stage1_locked;
	(void)fdt_addr;
	(void)fdt_allocated_size;
	(void)manifest_vm;
	(void)ppool;
	/* should never be called in SPMC */
	CHECK(false);
}
