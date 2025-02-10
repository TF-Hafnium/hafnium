/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vcpu.h"
#include "hf/vm.h"

/** Check validity of a FF-A direct message request. */
bool ffa_direct_msg_is_direct_request_valid(struct vcpu *current,
					    ffa_id_t sender_vm_id,
					    ffa_id_t receiver_vm_id);

/** Check validity of a FF-A direct message response. */
bool ffa_direct_msg_is_direct_response_valid(struct vcpu *current,
					     ffa_id_t sender_vm_id,
					     ffa_id_t receiver_vm_id);

bool ffa_direct_msg_is_direct_request_supported(struct vm *sender_vm,
						struct vm *receiver_vm,
						uint32_t func);

bool ffa_direct_msg_direct_request_forward(ffa_id_t receiver_vm_id,
					   struct ffa_value args,
					   struct ffa_value *ret);

void ffa_direct_msg_wind_call_chain_ffa_direct_req(
	struct vcpu_locked current_locked,
	struct vcpu_locked receiver_vcpu_locked, ffa_id_t sender_vm_id);

void ffa_direct_msg_unwind_call_chain_ffa_direct_resp(
	struct vcpu_locked current_locked, struct vcpu_locked next_locked);

bool ffa_direct_msg_handle_framework_msg(struct ffa_value args,
					 struct ffa_value *ret,
					 struct vcpu *current,
					 struct vcpu **next);

bool ffa_direct_msg_precedes_in_call_chain(struct vcpu_locked current_locked,
					   struct vcpu_locked target_locked);

bool ffa_direct_msg_is_spmd_lp_id(ffa_id_t vm_id);

bool ffa_direct_msg_handle_framework_msg_resp(struct ffa_value args,
					      struct ffa_value *ret,
					      struct vcpu_locked current_locked,
					      struct vcpu **next);
