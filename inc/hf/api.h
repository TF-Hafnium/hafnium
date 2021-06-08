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
#include "hf/vm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

void api_init(struct mpool *ppool);
void api_regs_state_saved(struct vcpu *vcpu);
int64_t api_mailbox_writable_get(const struct vcpu *current);
int64_t api_mailbox_waiter_get(ffa_vm_id_t vm_id, const struct vcpu *current);
int64_t api_debug_log(char c, struct vcpu *current);

struct vcpu *api_preempt(struct vcpu *current);
struct vcpu *api_wait_for_interrupt(struct vcpu *current);
struct vcpu *api_vcpu_off(struct vcpu *current);
struct vcpu *api_abort(struct vcpu *current);
struct vcpu *api_wake_up(struct vcpu *current, struct vcpu *target_vcpu);

int64_t api_interrupt_enable(uint32_t intid, bool enable,
			     enum interrupt_type type, struct vcpu *current);
uint32_t api_interrupt_get(struct vcpu *current);
int64_t api_interrupt_inject(ffa_vm_id_t target_vm_id,
			     ffa_vcpu_index_t target_vcpu_idx, uint32_t intid,
			     struct vcpu *current, struct vcpu **next);
int64_t api_interrupt_inject_locked(struct vcpu_locked target_locked,
				    uint32_t intid, struct vcpu *current,
				    struct vcpu **next);

struct ffa_value api_ffa_msg_send(ffa_vm_id_t sender_vm_id,
				  ffa_vm_id_t receiver_vm_id, uint32_t size,
				  uint32_t attributes, struct vcpu *current,
				  struct vcpu **next);
struct ffa_value api_ffa_msg_recv(bool block, struct vcpu *current,
				  struct vcpu **next);
struct ffa_value api_ffa_rx_release(struct vcpu *current, struct vcpu **next);
struct ffa_value api_vm_configure_pages(
	struct mm_stage1_locked mm_stage1_locked, struct vm_locked vm_locked,
	ipaddr_t send, ipaddr_t recv, uint32_t page_count,
	struct mpool *local_page_pool);
struct ffa_value api_ffa_rxtx_map(ipaddr_t send, ipaddr_t recv,
				  uint32_t page_count, struct vcpu *current,
				  struct vcpu **next);
struct ffa_value api_ffa_rxtx_unmap(ffa_vm_id_t allocator_id,
				    struct vcpu *current);
struct ffa_value api_yield(struct vcpu *current, struct vcpu **next);
struct ffa_value api_ffa_version(uint32_t requested_version);
struct ffa_value api_ffa_partition_info_get(struct vcpu *current,
					    const struct ffa_uuid *uuid);
struct ffa_value api_ffa_id_get(const struct vcpu *current);
struct ffa_value api_ffa_spm_id_get(void);
struct ffa_value api_ffa_features(uint32_t function_id);
struct ffa_value api_ffa_run(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			     const struct vcpu *current, struct vcpu **next);
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
				     ffa_vm_id_t sender_vm_id,
				     struct vcpu *current);
struct ffa_value api_ffa_mem_frag_tx(ffa_memory_handle_t handle,
				     uint32_t fragment_length,
				     ffa_vm_id_t sender_vm_id,
				     struct vcpu *current);
struct ffa_value api_ffa_msg_send_direct_req(ffa_vm_id_t sender_vm_id,
					     ffa_vm_id_t receiver_vm_id,
					     struct ffa_value args,
					     struct vcpu *current,
					     struct vcpu **next);
struct ffa_value api_ffa_msg_send_direct_resp(ffa_vm_id_t sender_vm_id,
					      ffa_vm_id_t receiver_vm_id,
					      struct ffa_value args,
					      struct vcpu *current,
					      struct vcpu **next);
struct ffa_value api_ffa_secondary_ep_register(ipaddr_t entry_point,
					       struct vcpu *current);
struct vcpu *api_switch_to_other_world(struct vcpu *current,
				       struct ffa_value other_world_ret,
				       enum vcpu_state vcpu_state);
struct ffa_value api_ffa_notification_bitmap_create(ffa_vm_id_t vm_id,
						    ffa_vcpu_count_t vcpu_count,
						    struct vcpu *current);
struct ffa_value api_ffa_notification_bitmap_destroy(ffa_vm_id_t vm_id,
						     struct vcpu *current);

struct ffa_value api_ffa_notification_update_bindings(
	ffa_vm_id_t sender_vm_id, ffa_vm_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, bool is_bind,
	struct vcpu *current);

struct ffa_value api_ffa_notification_set(
	ffa_vm_id_t sender_vm_id, ffa_vm_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, struct vcpu *current);

struct ffa_value api_ffa_notification_get(ffa_vm_id_t receiver_vm_id,
					  uint16_t vcpu_id, uint32_t flags,
					  struct vcpu *current);

struct ffa_value api_ffa_notification_info_get(struct vcpu *current);
