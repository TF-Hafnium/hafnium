/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/api.h"
#include "hf/check.h"
#include "hf/vm.h"

void ffa_interrupts_handle_secure_interrupt(struct vcpu *current,
					    struct vcpu **next)
{
	(void)current;
	(void)next;

	/*
	 * SPMD uses FFA_INTERRUPT ABI to convey secure interrupt to
	 * SPMC. Execution should not reach hypervisor with this ABI.
	 */
	CHECK(false);
}

bool ffa_interrupts_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vm_locked receiver_locked)
{
	(void)target_locked;
	(void)receiver_locked;

	return false;
}

/**
 * Enable relevant virtual interrupts for VMs.
 */
void ffa_interrupts_enable_virtual_interrupts(struct vcpu_locked current_locked,
					      struct vm_locked vm_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;

	if (vm_locked.vm->notifications.enabled) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_NOTIFICATION_PENDING_INTID);
	}
}

uint32_t ffa_interrupts_get(struct vcpu_locked current_locked)
{
	return api_interrupt_get(current_locked);
}

bool ffa_interrupts_intercept_call(struct vcpu_locked current_locked,
				   struct vcpu_locked next_locked,
				   struct ffa_value *signal_interrupt)
{
	(void)current_locked;
	(void)next_locked;
	(void)signal_interrupt;

	return false;
}
