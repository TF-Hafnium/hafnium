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
#include "hf/manifest.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

void plat_ffa_log_init(void);
void plat_ffa_set_tee_enabled(bool tee_enabled);
void plat_ffa_init(struct mpool *ppool);

/**
 * Forward normal world calls of FFA_RUN ABI to other world.
 */
bool plat_ffa_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret);

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

void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked);

struct ffa_value plat_ffa_yield_prepare(struct vcpu_locked current_locked,
					struct vcpu **next,
					uint32_t timeout_low,
					uint32_t timeout_high);

/**
 * FF-A v1.2 FFA_ERROR interface.
 * Implemented for SPMC in RTM_SP_INIT runtime model.
 */
struct ffa_value plat_ffa_error_32(struct vcpu *current, struct vcpu **next,
				   enum ffa_error error_code);

bool plat_ffa_is_spmd_lp_id(ffa_id_t vm_id);

/**
 * Reconfigure the interrupt belonging to the current partition at runtime.
 */
int64_t plat_ffa_interrupt_reconfigure(uint32_t int_id, uint32_t command,
				       uint32_t value, struct vcpu *current);

void plat_save_ns_simd_context(struct vcpu *vcpu);

uint32_t plat_ffa_interrupt_get(struct vcpu_locked current_locked);

bool plat_ffa_handle_framework_msg(struct ffa_value args,
				   struct ffa_value *ret);
