/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vcpu.h"

/**
 * Forward normal world calls of FFA_RUN ABI to other world.
 */
bool ffa_cpu_cycles_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
				struct ffa_value *ret);

struct ffa_value ffa_cpu_cycles_msg_wait_prepare(
	struct vcpu_locked current_locked, struct vcpu **next);

/**
 * Check if current SP can resume target VM/SP using FFA_RUN ABI.
 */
bool ffa_cpu_cycles_run_checks(struct vcpu_locked current_locked,
			       ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			       struct ffa_value *run_ret, struct vcpu **next);

/**
 * Perform checks for the state transition being requested by the Partition
 * based on it's runtime model and return false if an illegal transition is
 * being performed.
 */
bool ffa_cpu_cycles_check_runtime_state_transition(
	struct vcpu_locked current_locked, ffa_id_t vm_id,
	ffa_id_t receiver_vm_id, struct vcpu_locked locked_vcpu, uint32_t func,
	enum vcpu_state *next_state);

void ffa_cpu_cycles_init_schedule_mode_ffa_run(
	struct vcpu_locked current_locked, struct vcpu_locked target_locked);

struct ffa_value ffa_cpu_cycles_yield_prepare(struct vcpu_locked current_locked,
					      struct vcpu **next,
					      uint32_t timeout_low,
					      uint32_t timeout_high);

struct ffa_value ffa_cpu_cycles_error_32(struct vcpu *current,
					 struct vcpu **next,
					 enum ffa_error error_code);

struct ffa_value ffa_cpu_cycles_abort(struct vcpu_locked current_locked,
				      struct vcpu **next);

struct ffa_value ffa_partition_abort(struct vcpu *current, struct vcpu **next);
