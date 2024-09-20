/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/manifest.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

struct ffa_value plat_ffa_spmc_id_get(void)
{
	return (struct ffa_value){.func = FFA_ERROR_32,
				  .arg2 = FFA_NOT_SUPPORTED};
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_id_t caller_id, const struct vm *target)
{
	(void)caller_id;
	(void)target;
	return 0;
}

void plat_ffa_log_init(void)
{
}

void plat_ffa_set_tee_enabled(bool tee_enabled)
{
	(void)tee_enabled;
}

void plat_ffa_init(struct mpool *ppool)
{
	(void)ppool;
}

/**
 * Check validity of the FF-A memory send function attempt.
 */
bool plat_ffa_is_memory_send_valid(ffa_id_t receiver_vm_id, uint32_t share_func)
{
	(void)receiver_vm_id;
	(void)share_func;

	return false;
}

/**
 * Check validity of a FF-A direct message request.
 */
bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_id_t sender_vm_id,
				      ffa_id_t receiver_vm_id)
{
	(void)current;
	(void)sender_vm_id;
	(void)receiver_vm_id;

	return false;
}

bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm, uint32_t func)
{
	(void)sender_vm;
	(void)receiver_vm;
	(void)func;

	return false;
}

/**
 * Check validity of a FF-A direct message response.
 */
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id)
{
	(void)current;
	(void)sender_vm_id;
	(void)receiver_vm_id;

	return false;
}

bool plat_ffa_is_notifications_bitmap_access_valid(struct vcpu *current,
						   ffa_id_t vm_id)
{
	(void)current;
	(void)vm_id;

	return false;
}

void plat_ffa_rxtx_map_forward(struct vm_locked vm_locked)
{
	(void)vm_locked;
}

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked)
{
	(void)to_destroy_locked;
}

void plat_ffa_rxtx_unmap_forward(struct vm_locked vm_locked)
{
	(void)vm_locked;
}

bool plat_ffa_direct_request_forward(ffa_id_t receiver_vm_id,
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

bool plat_ffa_msg_send2_forward(ffa_id_t receiver_vm_id, ffa_id_t sender_vm_id,
				struct ffa_value *ret)
{
	(void)receiver_vm_id;
	(void)sender_vm_id;
	(void)ret;

	return false;
}

ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index)
{
	return index | FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
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

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_id_t sender_id,
					  ffa_id_t receiver_id)
{
	(void)current;
	(void)sender_id;
	(void)receiver_id;
	return false;
}

bool plat_ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id, uint32_t flags,
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
					ffa_id_t sender_id,
					ffa_id_t receiver_id)
{
	(void)current;
	(void)sender_id;
	(void)receiver_id;
	return false;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_id_t receiver_id, uint32_t flags)
{
	(void)flags;
	(void)current;
	(void)receiver_id;
	return false;
}

bool plat_ffa_notifications_get_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	const ffa_notifications_bitmap_t *from_sp, struct ffa_value *ret)
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
	uint32_t flags, struct ffa_value *ret)
{
	(void)receiver_locked;
	(void)from_fwk;
	(void)flags;
	(void)ret;

	return false;
}

bool plat_ffa_notification_set_forward(ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id, uint32_t flags,
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
	ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool plat_ffa_notifications_bitmap_create_call(ffa_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return false;
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct vm_locked plat_ffa_vm_find_locked(ffa_id_t vm_id)
{
	(void)vm_id;
	return (struct vm_locked){.vm = NULL};
}

struct vm_locked plat_ffa_vm_find_locked_create(ffa_id_t vm_id)
{
	(void)vm_id;
	return (struct vm_locked){.vm = NULL};
}

bool plat_ffa_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	(void)vm_id;
	(void)vcpu_idx;
	(void)ret;

	return false;
}

bool plat_ffa_vm_notifications_info_get(const uint16_t *ids,
					const uint32_t *ids_count,
					const uint32_t *lists_sizes,
					const uint32_t *lists_count,
					const uint32_t ids_count_max)
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
bool plat_ffa_run_checks(struct vcpu_locked current_locked,
			 ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			 struct ffa_value *run_ret, struct vcpu **next)
{
	(void)current_locked;
	(void)target_vm_id;
	(void)run_ret;
	(void)next;
	(void)vcpu_idx;
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
	 * SPMD uses FFA_INTERRUPT ABI to convey secure interrupt to SPMC.
	 * Execution not expected to reach here.
	 */
	CHECK(false);

	return ffa_error(FFA_NOT_SUPPORTED);
}

void plat_ffa_notification_info_get_forward(const uint16_t *ids,
					    const uint32_t *ids_count,
					    const uint32_t *lists_sizes,
					    const uint32_t *lists_count,
					    const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;
}

void plat_ffa_sri_init(void)
{
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

bool plat_ffa_partition_info_get_forward(const struct ffa_uuid *uuid,
					 const uint32_t flags,
					 const ffa_vm_count_t *ret_count)
{
	(void)uuid;
	(void)flags;
	(void)ret_count;

	return false;
}

bool plat_ffa_partition_info_get_regs_forward(	// NOLINTNEXTLINE
	const struct ffa_uuid *uuid,
	const uint16_t start_index,  // NOLINTNEXTLINE
	const uint16_t tag,
	struct ffa_partition_info *partitions,		     // NOLINTNEXTLINE
	uint16_t partitions_len, ffa_vm_count_t *ret_count)  // NOLINTNEXTLINE
{
	(void)uuid;
	(void)start_index;
	(void)tag;
	(void)partitions;
	(void)partitions_len;
	(void)ret_count;

	return true;
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
}

struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu_locked current_locked,
					   struct vcpu **next)
{
	(void)current_locked;
	(void)next;

	return (struct ffa_value){.func = FFA_INTERRUPT_32};
}

bool plat_ffa_check_runtime_state_transition(struct vcpu_locked current_locked,
					     ffa_id_t vm_id,
					     ffa_id_t receiver_vm_id,
					     struct vcpu_locked receiver_locked,
					     uint32_t func,  // NOLINTNEXTLINE
					     enum vcpu_state *next_state)
{
	(void)current_locked;
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_locked;
	(void)func;
	(void)next_state;

	return true;
}

void plat_ffa_init_schedule_mode_ffa_run(struct vcpu_locked current_locked,
					 struct vcpu_locked target_locked)
{
	(void)current_locked;
	(void)target_locked;
}

void plat_ffa_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id)
{
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
	(void)current_locked;
	(void)next_locked;
}

void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked)
{
	(void)current_locked;
	(void)vm_locked;
}

struct ffa_value plat_ffa_other_world_mem_send(
	struct vm *from, struct ffa_memory_region *memory_region,
	uint32_t length, uint32_t fragment_length, struct mpool *page_pool)
{
	(void)from;
	(void)memory_region;
	(void)length;
	(void)fragment_length;
	(void)page_pool;

	return (struct ffa_value){.func = FFA_ERROR_32};
}

struct ffa_value plat_ffa_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	(void)handle;
	(void)flags;
	(void)page_pool;
	(void)to;

	return ffa_error(FFA_INVALID_PARAMETERS);
}

struct ffa_value plat_ffa_other_world_mem_send_continue(
	struct vm *from, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct mpool *page_pool)
{
	(void)from;
	(void)fragment;
	(void)fragment_length;
	(void)handle;
	(void)page_pool;

	return ffa_error(FFA_INVALID_PARAMETERS);
}

struct ffa_value plat_ffa_msg_send(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id, uint32_t size,
				   struct vcpu *current, struct vcpu **next)
{
	(void)sender_vm_id;
	(void)receiver_vm_id;
	(void)size;
	(void)current;
	(void)next;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_yield_prepare(struct vcpu current_locked,
					struct vcpu **next,
					uint32_t timeout_low,
					uint32_t timeout_high)
{
	(void)current_locked;
	(void)next;
	(void)timeout_low;
	(void)timeout_high;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_error_32(struct vcpu *current, struct vcpu **next,
				   enum ffa_error error_code)
{
	(void)current;
	(void)next;
	(void)error_code;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_msg_recv(bool block, struct vcpu *current,
				   struct vcpu **next)
{
	(void)block;
	(void)current;
	(void)next;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool plat_ffa_partition_info_get_regs_forward_allowed(void)
{
	return false;
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
