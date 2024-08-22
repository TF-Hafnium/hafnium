/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/hf_ipi.h"

#include "hf/cpu.h"
#include "hf/plat/interrupts.h"

/** Interrupt priority for Inter-Processor Interrupt. */
#define IPI_PRIORITY 0x0U

/**
 * Initialize the IPI SGI.
 */
void hf_ipi_init_interrupt(void)
{
	/* Configure as a Secure SGI. */
	struct interrupt_descriptor ipi_desc = {
		.interrupt_id = HF_IPI_INTID,
		.type = INT_DESC_TYPE_SGI,
		.sec_state = INT_DESC_SEC_STATE_S,
		.priority = IPI_PRIORITY,
		.valid = true,
	};

	plat_interrupts_configure_interrupt(ipi_desc);
}

/**
 * Returns the target_vcpu for the pending IPI on the current CPU and
 * resets the item in the list to NULL to show it has been retrieved.
 */
struct vcpu *hf_ipi_get_pending_target_vcpu(struct cpu *current)
{
	struct vcpu *ret = current->ipi_target_vcpu;

	current->ipi_target_vcpu = NULL;
	return ret;
}

/**
 * Send and record the IPI for the target vCPU.
 */
void hf_ipi_send_interrupt(struct vm *vm, ffa_vcpu_index_t target_vcpu_index)
{
	struct vcpu *target_vcpu = vm_get_vcpu(vm, target_vcpu_index);
	struct cpu *target_cpu = target_vcpu->cpu;

	target_cpu->ipi_target_vcpu = target_vcpu;
	plat_interrupts_send_sgi(HF_IPI_INTID, target_cpu, true);
}

/**
 * IPI IRQ specific handling for the secure interrupt for each vCPU state:
 *   - RUNNING: Continue secure interrupt handling as normal, injecting
 *   a virtual interrupt to the vCPU.
 *   - Other states are not currently supported so exit the handler.
 * Returns True if the IPI SGI has been handled.
 * False if further secure interrupt handling is required.
 */
bool hf_ipi_handle(struct vcpu_locked target_vcpu_locked)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;

	switch (target_vcpu->state) {
	case VCPU_STATE_RUNNING:
		return false;
	default:
		dlog_verbose(
			"IPIs not currently supported for when the target_vcpu "
			"is in the state %d\n",
			target_vcpu->state);
		/*
		 * Mark the interrupt as completed so it can be signalled again.
		 */
		plat_interrupts_end_of_interrupt(HF_IPI_INTID);
		return true;
	}
}
