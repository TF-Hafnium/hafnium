/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/cpu.h"
#include "hf/mpool.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

static inline struct ffa_value api_ffa_interrupt_return(uint32_t id)
{
	return (struct ffa_value){.func = FFA_INTERRUPT_32, .arg2 = id};
}

void api_init(struct mpool *ppool);
struct vcpu *api_ffa_get_vm_vcpu(struct vm *vm, struct vcpu *current);
void api_regs_state_saved(struct vcpu *vcpu);
int64_t api_mailbox_writable_get(const struct vcpu *current);
int64_t api_mailbox_waiter_get(ffa_id_t vm_id, const struct vcpu *current);
struct vcpu *api_switch_to_vm(struct vcpu_locked current_locked,
			      struct ffa_value to_ret,
			      enum vcpu_state vcpu_state, ffa_id_t to_id);
struct vcpu *api_switch_to_primary(struct vcpu_locked current_locked,
				   struct ffa_value primary_ret,
				   enum vcpu_state secondary_state);

struct vcpu *api_preempt(struct vcpu *current);
struct vcpu *api_wait_for_interrupt(struct vcpu *current);
struct vcpu *api_vcpu_off(struct vcpu *current);
struct vcpu *api_abort(struct vcpu *current);
struct vcpu *api_wake_up(struct vcpu *current, struct vcpu *target_vcpu);

int64_t api_interrupt_enable(uint32_t intid, bool enable,
			     enum interrupt_type type, struct vcpu *current);
uint32_t api_interrupt_get(struct vcpu_locked current_locked);
int64_t api_interrupt_inject(ffa_id_t target_vm_id,
			     ffa_vcpu_index_t target_vcpu_idx, uint32_t intid,
			     struct vcpu *current, struct vcpu **next);
int64_t api_interrupt_inject_locked(struct vcpu_locked target_locked,
				    uint32_t intid,
				    struct vcpu_locked current_locked,
				    struct vcpu **next);
int64_t api_hf_interrupt_send_ipi(uint32_t target_vcpu_id,
				  struct vcpu *current);

struct ffa_value api_ffa_msg_send(ffa_id_t sender_vm_id,
				  ffa_id_t receiver_vm_id, uint32_t size,
				  struct vcpu *current, struct vcpu **next);
struct ffa_value api_ffa_msg_send2(ffa_id_t sender_vm_id, uint32_t flags,
				   struct vcpu *current);
struct ffa_value api_ffa_rx_release(ffa_id_t receiver_id, struct vcpu *current);
struct ffa_value api_ffa_rx_acquire(ffa_id_t receiver_id, struct vcpu *current);
struct ffa_value api_vm_configure_pages(
	struct mm_stage1_locked mm_stage1_locked, struct vm_locked vm_locked,
	ipaddr_t send, ipaddr_t recv, uint32_t page_count,
	struct mpool *local_page_pool);
struct ffa_value api_ffa_rxtx_map(ipaddr_t send, ipaddr_t recv,
				  uint32_t page_count, struct vcpu *current);
struct ffa_value api_ffa_rxtx_unmap(ffa_id_t allocator_id,
				    struct vcpu *current);
struct ffa_value api_yield(struct vcpu *current, struct vcpu **next,
			   struct ffa_value *args);
struct ffa_value api_ffa_version(struct vcpu *current,
				 uint32_t requested_version);
struct ffa_value api_ffa_partition_info_get(struct vcpu *current,
					    const struct ffa_uuid *uuid,
					    uint32_t flags);
bool api_ffa_fill_partition_info_from_regs(
	struct ffa_value ret, uint16_t start_index,
	struct ffa_partition_info *partitions, uint16_t partitions_len,
	ffa_vm_count_t *ret_count);
struct ffa_value api_ffa_partition_info_get_regs(struct vcpu *current,
						 const struct ffa_uuid *uuid,
						 uint16_t start_index,
						 uint16_t tag);
struct ffa_value api_ffa_id_get(const struct vcpu *current);
struct ffa_value api_ffa_spm_id_get(void);
struct ffa_value api_ffa_feature_success(uint32_t arg2);
struct ffa_value api_ffa_features(uint32_t function_or_feature_id,
				  uint32_t input_property,
				  struct vcpu *current);
struct ffa_value api_ffa_msg_wait(struct vcpu *current, struct vcpu **next,
				  struct ffa_value *args);
struct ffa_value api_ffa_run(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			     struct vcpu *current, struct vcpu **next);
struct ffa_value api_ffa_mem_send(uint32_t share_func, uint32_t length,
				  uint32_t fragment_length, ipaddr_t address,
				  uint32_t page_count, struct vcpu *current);
struct ffa_value api_ffa_mem_retrieve_req(uint32_t length,
					  uint32_t fragment_length,
					  ipaddr_t address, uint32_t page_count,
					  struct vcpu *current);
struct ffa_value api_ffa_mem_relinquish(struct vcpu *current);
struct ffa_value api_ffa_mem_reclaim(ffa_memory_handle_t handle,
				     ffa_memory_region_flags_t flags,
				     struct vcpu *current);
struct ffa_value api_ffa_mem_frag_rx(ffa_memory_handle_t handle,
				     uint32_t fragment_offset,
				     ffa_id_t sender_vm_id,
				     struct vcpu *current);
struct ffa_value api_ffa_mem_frag_tx(ffa_memory_handle_t handle,
				     uint32_t fragment_length,
				     ffa_id_t sender_vm_id,
				     struct vcpu *current);
struct ffa_value api_ffa_msg_send_direct_req(struct ffa_value args,
					     struct vcpu *current,
					     struct vcpu **next);
struct ffa_value api_ffa_msg_send_direct_resp(struct ffa_value args,
					      struct vcpu *current,
					      struct vcpu **next);
struct ffa_value api_ffa_secondary_ep_register(ipaddr_t entry_point,
					       struct vcpu *current);
struct vcpu *api_switch_to_other_world(struct vcpu_locked current_locked,
				       struct ffa_value other_world_ret,
				       enum vcpu_state vcpu_state);
struct ffa_value api_ffa_notification_bitmap_create(ffa_id_t vm_id,
						    ffa_vcpu_count_t vcpu_count,
						    struct vcpu *current);
struct ffa_value api_ffa_notification_bitmap_destroy(ffa_id_t vm_id,
						     struct vcpu *current);

struct ffa_value api_ffa_notification_update_bindings(
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, bool is_bind,
	struct vcpu *current);

struct ffa_value api_ffa_notification_set(
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, struct vcpu *current);

struct ffa_value api_ffa_notification_get(ffa_id_t receiver_vm_id,
					  uint16_t vcpu_id, uint32_t flags,
					  struct vcpu *current);

struct ffa_value api_ffa_notification_info_get(struct vcpu *current);

struct ffa_value api_ffa_mem_perm_get(vaddr_t base_addr, struct vcpu *current);
struct ffa_value api_ffa_mem_perm_set(vaddr_t base_addr, uint32_t page_count,
				      uint32_t mem_perm, struct vcpu *current);

void api_flush_log_buffer(struct vcpu_locked *vcpu_locked);
struct ffa_value api_ffa_console_log(struct ffa_value args,
				     struct vcpu *current);

void api_ffa_resume_direct_resp_target(struct vcpu_locked current_locked,
				       struct vcpu **next,
				       ffa_id_t receiver_vm_id,
				       struct ffa_value to_ret,
				       bool is_nwd_call_chain);

bool api_extended_args_are_zero(struct ffa_value *args);
