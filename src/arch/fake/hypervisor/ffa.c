/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "hf/arch/plat/ffa.h"

#include "hf/ffa_internal.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

struct ffa_value arch_ffa_features(uint32_t function_id)
{
	(void)function_id;
	return ffa_error(FFA_NOT_SUPPORTED);
}

ffa_vm_id_t arch_ffa_spmc_id_get(void)
{
	return HF_SPMC_VM_ID;
}

void plat_ffa_log_init(void)
{
}

bool plat_ffa_is_memory_send_valid(ffa_vm_id_t receiver_vm_id,
				   uint32_t share_func)
{
	(void)receiver_vm_id;
	(void)share_func;

	return true;
}

bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_vm_id_t sender_vm_id,
				      ffa_vm_id_t receiver_vm_id)
{
	(void)current;
	(void)sender_vm_id;
	(void)receiver_vm_id;

	return true;
}

bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm)
{
	(void)sender_vm;
	(void)receiver_vm;

	return false;
}

bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id)
{
	(void)current;
	(void)sender_vm_id;
	(void)receiver_vm_id;

	return true;
}

bool plat_ffa_run_forward(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	(void)vm_id;
	(void)vcpu_idx;
	(void)ret;

	return false;
}

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked)
{
	(void)to_destroy_locked;
}

void plat_ffa_rxtx_unmap_forward(ffa_vm_id_t id)
{
	(void)id;
}

bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret)
{
	(void)receiver_vm_id;
	(void)args;
	(void)ret;
	return false;
}

bool plat_ffa_rx_release_forward(struct vm_locked vm_locked,
				 struct ffa_value *ret)
{
	(void)vm_locked;
	(void)ret;

	return false;
}

bool plat_ffa_rx_release_forwarded(struct vm_locked vm_locked)
{
	(void)vm_locked;

	return false;
}

bool plat_ffa_acquire_receiver_rx(struct vm_locked to_locked,
				  struct ffa_value *ret)
{
	(void)to_locked;
	(void)ret;

	return false;
}

bool plat_ffa_is_indirect_msg_supported(struct vm_locked sender_locked,
					struct vm_locked receiver_locked)
{
	(void)sender_locked;
	(void)receiver_locked;

	return false;
}

bool plat_ffa_msg_send2_forward(ffa_vm_id_t receiver_vm_id,
				ffa_vm_id_t sender_vm_id, struct ffa_value *ret)
{
	(void)receiver_vm_id;
	(void)sender_vm_id;
	(void)ret;

	return false;
}

ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index)
{
	return index;
}

bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle)
{
	(void)handle;
	return false;
}

uint32_t plat_ffa_other_world_mode(void)
{
	return 0U;
}

uint32_t plat_ffa_owner_world_mode(ffa_vm_id_t owner_id)
{
	(void)owner_id;
	return 0U;
}

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id)
{
	(void)current;
	(void)sender_id;
	(void)receiver_id;
	return false;
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

void plat_ffa_rxtx_map_forward(struct vm_locked vm_locked)
{
	(void)vm_locked;
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t vm_id, const struct vm *target)
{
	(void)vm_id;
	(void)target;
	return 0;
}

bool plat_ffa_vm_managed_exit_supported(struct vm *vm)
{
	(void)vm;
	return false;
}

bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id)
{
	(void)current;
	(void)vm_id;

	return false;
}

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id)
{
	(void)current;
	(void)sender_id;
	(void)receiver_id;
	return false;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id, uint32_t flags)
{
	(void)flags;
	(void)current;
	(void)receiver_id;
	return false;
}

bool plat_ffa_notifications_get_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	ffa_notifications_bitmap_t *from_sp,  // NOLINT
	struct ffa_value *ret)		      // NOLINT
{
	(void)receiver_locked;
	(void)vcpu_id;
	(void)from_sp;
	(void)ret;

	return false;
}

bool plat_ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked,
	ffa_notifications_bitmap_t *from_fwk,  // NOLINT
	uint32_t flags, ffa_vcpu_index_t vcpu_id, struct ffa_value *ret)
{
	(void)receiver_locked;
	(void)from_fwk;
	(void)flags;
	(void)vcpu_id;
	(void)ret;

	return false;
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

struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id)
{
	(void)vm_id;
	return (struct vm_locked){.vm = NULL};
}

struct vm_locked plat_ffa_vm_find_locked_create(ffa_vm_id_t vm_id)
{
	(void)vm_id;
	return (struct vm_locked){.vm = NULL};
}

bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id)
{
	(void)vm_id;
	return false;
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
	return false;
}

bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current)
{
	(void)current;
	return false;
}

/**
 * Check if current VM can resume target VM/SP using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu *current, ffa_vm_id_t target_vm_id,
			 ffa_vcpu_index_t vcpu_idx, struct ffa_value *run_ret,
			 struct vcpu **next)
{
	(void)current;
	(void)target_vm_id;
	(void)run_ret;
	(void)next;
	(void)vcpu_idx;
	return true;
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

void plat_ffa_sri_state_set(enum plat_ffa_sri_state state)
{
	(void)state;
}

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

void plat_ffa_partition_info_get_forward(  // NOLINTNEXTLINE
	const struct ffa_uuid *uuid,	   // NOLINTNEXTLINE
	const uint32_t flags,		   // NOLINTNEXTLINE
	struct ffa_partition_info *partitions, ffa_vm_count_t *ret_count)
{
	(void)uuid;
	(void)flags;
	(void)partitions;
	(void)ret_count;
}

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

bool plat_ffa_check_runtime_state_transition(struct vcpu *current,
					     ffa_vm_id_t vm_id,
					     ffa_vm_id_t receiver_vm_id,
					     struct vcpu *receiver_vcpu,
					     uint32_t func,  // NOLINTNEXTLINE
					     enum vcpu_state *next_state)
{
	/* Perform state transition checks only for Secure Partitions. */
	(void)current;
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_vcpu;
	(void)func;
	(void)next_state;

	return true;
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
