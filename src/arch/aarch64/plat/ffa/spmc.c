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

const uint32_t nwd_vms_size = ARRAY_SIZE(nwd_vms);

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (SPMC)\n");
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
