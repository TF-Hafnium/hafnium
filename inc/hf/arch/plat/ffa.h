/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/ffa.h"
#include "hf/ffa_memory_internal.h"
#include "hf/manifest.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

/** Returns the SPMC ID. */
struct ffa_value plat_ffa_spmc_id_get(void);

void plat_ffa_log_init(void);
void plat_ffa_set_tee_enabled(bool tee_enabled);
void plat_ffa_init(struct mpool *ppool);
bool plat_ffa_is_memory_send_valid(ffa_id_t receiver, ffa_id_t sender,
				   uint32_t share_func, bool multiple_borrower);

bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_id_t sender_vm_id,
				      ffa_id_t receiver_vm_id);
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id);
bool plat_ffa_is_direct_request_supported(struct vm *sender_vm,
					  struct vm *receiver_vm,
					  uint32_t func);
bool plat_ffa_direct_request_forward(ffa_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret);

bool plat_ffa_rx_release_forward(struct vm_locked vm_locked,
				 struct ffa_value *ret);

bool plat_ffa_acquire_receiver_rx(struct vm_locked locked,
				  struct ffa_value *ret);

bool plat_ffa_is_indirect_msg_supported(struct vm_locked sender_locked,
					struct vm_locked receiver_locked);

bool plat_ffa_msg_send2_forward(ffa_id_t receiver_vm_id, ffa_id_t sender_vm_id,
				struct ffa_value *ret);

struct ffa_value plat_ffa_is_notifications_bitmap_access_valid(
	struct vcpu *current, ffa_id_t vm_id);

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_id_t sender_id,
					  ffa_id_t receiver_id);
bool plat_ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret);

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_id_t sender_id,
					ffa_id_t receiver_id);

bool plat_ffa_notification_set_forward(ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id, uint32_t flags,
				       ffa_notifications_bitmap_t bitmap,
				       struct ffa_value *ret);

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_id_t receiver_id, uint32_t flags);

bool plat_ffa_notifications_get_from_sp(struct vm_locked receiver_locked,
					ffa_vcpu_index_t vcpu_id,
					ffa_notifications_bitmap_t *from_sp,
					struct ffa_value *ret);

bool plat_ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	uint32_t flags, ffa_vcpu_index_t vcpu_id, struct ffa_value *ret);

void plat_ffa_rxtx_map_forward(struct vm_locked vm_locked);

void plat_ffa_vm_destroy(struct vm_locked to_destroy_locked);

void plat_ffa_rxtx_unmap_forward(struct vm_locked vm_locked);

/**
 * Checks whether managed exit is supported by given SP.
 */
bool plat_ffa_vm_managed_exit_supported(struct vm *vm);

/**
 * Encodes memory handle according to section 5.10.2 of the FF-A v1.0 spec.
 */
ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index);

/**
 * Checks whether given handle was allocated by current world, according to
 * handle encoding rules.
 */
bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle);

/**
 * For non-secure memory, retrieve the NS mode if the partition manager supports
 * it. The SPMC will return MM_MODE_NS, and the hypervisor 0 as it only deals
 * with NS accesses by default.
 */
uint32_t plat_ffa_other_world_mode(void);

/**
 * Return the FF-A partition info VM/SP properties given the VM id.
 */
ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_id_t caller_id, const struct vm *target);

/**
 * Get NWd VM's structure.
 */
struct vm_locked plat_ffa_vm_find_locked(ffa_id_t vm_id);

struct vm_locked plat_ffa_vm_find_locked_create(ffa_id_t vm_id);

/**
 * Creates a bitmap for the VM of the given ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count);

/**
 * Issues a FFA_NOTIFICATION_BITMAP_CREATE.
 * Returns true if the call goes well, and false if call returns with
 * FFA_ERROR_32.
 */
bool plat_ffa_notifications_bitmap_create_call(ffa_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count);

/**
 * Destroys the notifications bitmap for the given VM ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_id_t vm_id);

/**
 * Helper to get the struct notifications, depending on the sender's id.
 */
struct notifications *plat_ffa_vm_get_notifications_senders_world(
	struct vm_locked vm_locked, ffa_id_t sender_id);

/**
 * Forward normal world calls of FFA_RUN ABI to other world.
 */
bool plat_ffa_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret);

bool plat_ffa_notification_info_get_call(struct ffa_value *ret);

bool plat_ffa_vm_notifications_info_get(uint16_t *ids, uint32_t *ids_count,
					uint32_t *lists_sizes,
					uint32_t *lists_count,
					uint32_t ids_count_max);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if there has been
 * a call to FFA_NOTIFICATION_SET, and the SRI has been delayed.
 * To be called at a context switch to the NWd.
 */
void plat_ffa_sri_trigger_if_delayed(struct cpu *cpu);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if it hasn't been
 * delayed in call to FFA_NOTIFICATION_SET.
 */
void plat_ffa_sri_trigger_not_delayed(struct cpu *cpu);

/**
 * Track that in current CPU there was a notification set with delay SRI
 * flag.
 */
void plat_ffa_sri_set_delayed(struct cpu *cpu);

/**
 * Initialize Schedule Receiver Interrupts needed in the context of
 * notifications support.
 */
void plat_ffa_sri_init(struct cpu *cpu);

void plat_ffa_notification_info_get_forward(uint16_t *ids, uint32_t *ids_count,
					    uint32_t *lists_sizes,
					    uint32_t *lists_count,
					    uint32_t ids_count_max);

bool plat_ffa_is_mem_perm_get_valid(const struct vcpu *current);
bool plat_ffa_is_mem_perm_set_valid(const struct vcpu *current);

struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu_locked current_locked,
					   struct vcpu **next);

/**
 * Check if current SP can resume target VM/SP using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu_locked current_locked,
			 ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			 struct ffa_value *run_ret, struct vcpu **next);

/**
 * Deactivate interrupt.
 */
int64_t plat_ffa_interrupt_deactivate(uint32_t pint_id, uint32_t vint_id,
				      struct vcpu *current);

void plat_ffa_handle_secure_interrupt(struct vcpu *current, struct vcpu **next);
bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked next_locked, struct vcpu_locked current_locked,
	struct vm_locked receiver_locked);

bool plat_ffa_intercept_call(struct vcpu_locked current_locked,
			     struct vcpu_locked next_locked,
			     struct ffa_value *signal_interrupt);

bool plat_ffa_partition_info_get_regs_forward_allowed(void);

void plat_ffa_partition_info_get_forward(const struct ffa_uuid *uuid,
					 uint32_t flags,
					 struct ffa_partition_info *partitions,
					 ffa_vm_count_t *ret_count);

void plat_ffa_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
				       paddr_t fdt_addr,
				       size_t fdt_allocated_size,
				       const struct manifest_vm *manifest_vm,
				       const struct boot_params *boot_params,
				       struct mpool *ppool);

/**
 * Returns true if the FFA_SECONDARY_EP_REGISTER interface is supported at
 * the virtual FF-A instance.
 */
bool plat_ffa_is_secondary_ep_register_supported(void);

/**
 * Perform checks for the state transition being requested by the Partition
 * based on it's runtime model and return false if an illegal transition is
 * being performed.
 */
bool plat_ffa_check_runtime_state_transition(struct vcpu_locked current_locked,
					     ffa_id_t vm_id,
					     ffa_id_t receiver_vm_id,
					     struct vcpu_locked locked_vcpu,
					     uint32_t func,
					     enum vcpu_state *next_state);

struct vcpu *plat_ffa_unwind_nwd_call_chain_interrupt(struct vcpu *current);
void plat_ffa_init_schedule_mode_ffa_run(struct vcpu_locked current_locked,
					 struct vcpu_locked target_locked);

void plat_ffa_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id);

void plat_ffa_unwind_call_chain_ffa_direct_resp(
	struct vcpu_locked current_locked, struct vcpu_locked next_locked);

void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked);

/*
 * Handles FF-A memory share calls with recipients from the other world.
 */
struct ffa_value plat_ffa_other_world_mem_send(
	struct vm *from, uint32_t share_func,
	struct ffa_memory_region **memory_region, uint32_t length,
	uint32_t fragment_length, struct mpool *page_pool);

/**
 * Handles the memory reclaim if a memory handle from the other world is
 * provided.
 */
struct ffa_value plat_ffa_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool);

/**
 * Handles the continuation of the memory send operation in case the memory
 * region descriptor contains multiple segments.
 */
struct ffa_value plat_ffa_other_world_mem_send_continue(
	struct vm *from, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct mpool *page_pool);

/**
 * This FF-A v1.0 FFA_MSG_SEND interface.
 * Implemented for the Hypervisor, but not in the SPMC.
 */
struct ffa_value plat_ffa_msg_send(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id, uint32_t size,
				   struct vcpu *current, struct vcpu **next);

struct ffa_value plat_ffa_yield_prepare(struct vcpu_locked current_locked,
					struct vcpu **next,
					uint32_t timeout_low,
					uint32_t timeout_high);

ffa_memory_attributes_t plat_ffa_memory_security_mode(
	ffa_memory_attributes_t attributes, uint32_t mode);

/**
 * FF-A v1.2 FFA_ERROR interface.
 * Implemented for SPMC in RTM_SP_INIT runtime model.
 */
struct ffa_value plat_ffa_error_32(struct vcpu *current, struct vcpu **next,
				   enum ffa_error error_code);

bool plat_ffa_is_spmd_lp_id(ffa_id_t vm_id);

struct ffa_value plat_ffa_msg_recv(bool block,
				   struct vcpu_locked current_locked,
				   struct vcpu **next);

int64_t plat_ffa_mailbox_writable_get(const struct vcpu *current);

int64_t plat_ffa_mailbox_waiter_get(ffa_id_t vm_id, const struct vcpu *current);

/**
 * Reconfigure the interrupt belonging to the current partition at runtime.
 */
int64_t plat_ffa_interrupt_reconfigure(uint32_t int_id, uint32_t command,
				       uint32_t value, struct vcpu *current);

/**
 * Reclaim all resources belonging to VM in aborted state.
 */
void plat_ffa_free_vm_resources(struct vm_locked vm_locked);

void plat_save_ns_simd_context(struct vcpu *vcpu);

uint32_t plat_ffa_interrupt_get(struct vcpu_locked current_locked);

bool plat_ffa_handle_framework_msg(struct ffa_value args,
				   struct ffa_value *ret);
