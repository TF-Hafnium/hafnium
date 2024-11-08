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
int64_t plat_ffa_interrupt_deactivate(uint32_t pint_id, uint32_t vint_id,
				      struct vcpu *current);

void plat_ffa_handle_secure_interrupt(struct vcpu *current, struct vcpu **next);
bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked next_locked, struct vcpu_locked current_locked,
	struct vm_locked receiver_locked);

bool plat_ffa_intercept_call(struct vcpu_locked current_locked,
			     struct vcpu_locked next_locked,
			     struct ffa_value *signal_interrupt);

struct vcpu *plat_ffa_unwind_nwd_call_chain_interrupt(struct vcpu *current);

void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked);

/**
 * Reconfigure the interrupt belonging to the current partition at runtime.
 */
int64_t plat_ffa_interrupt_reconfigure(uint32_t int_id, uint32_t command,
				       uint32_t value, struct vcpu *current);

uint32_t plat_ffa_interrupt_get(struct vcpu_locked current_locked);
