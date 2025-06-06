/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

/**
 * Deactivate interrupt.
 */
int64_t ffa_interrupts_deactivate(uint32_t pint_id, uint32_t vint_id,
				  struct vcpu *current);

void ffa_interrupts_handle_secure_interrupt(struct vcpu *current,
					    struct vcpu **next);
bool ffa_interrupts_inject_notification_pending_interrupt(
	struct vcpu_locked next_locked, struct vm_locked receiver_locked);

bool ffa_interrupts_intercept_call(struct vcpu_locked current_locked,
				   struct vcpu_locked next_locked,
				   struct ffa_value *interrupt_ret);

struct vcpu *ffa_interrupts_unwind_nwd_call_chain(struct vcpu *current);

void ffa_interrupts_enable_virtual_interrupts(struct vcpu_locked current_locked,
					      struct vm_locked vm_locked);
void ffa_interrupts_mask(struct vcpu_locked receiver_vcpu_locked);
void ffa_interrupts_unmask(struct vcpu *current);
/**
 * Reconfigure the interrupt belonging to the current partition at runtime.
 */
int64_t ffa_interrupts_reconfigure(uint32_t int_id, uint32_t command,
				   uint32_t value, struct vcpu *current);
