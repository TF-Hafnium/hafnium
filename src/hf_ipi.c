/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/hf_ipi.h"

#include "hf/cpu.h"
#include "hf/ffa/notifications.h"
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
		.enabled = true,
	};

	plat_interrupts_configure_interrupt(ipi_desc);
}

/**
 * Returns the next target_vcpu with a pending IPI and removes it from
 * the list for the current CPU to show it has been retrieved.
 * The running vCPU is prioritised to prevent it being put into
 * the PREEMPTED state before it has handled it's IPI, this could happen in
 * the case a vCPU in the WAITING state also has a pending IPI.
 * In the case of a spurious IPI physical interrupt, where the target
 * vCPUs have already handled their pending IPIs return NULL.
 */
struct vcpu *hf_ipi_get_pending_target_vcpu(struct vcpu *current)
{
	struct list_entry *list;
	struct vcpu *target_vcpu;

	/* Lock the CPU the list belongs to. */
	sl_lock(&current->cpu->lock);

	/*
	 * Check if the current vcpu has a pending interrupt,
	 * if so prioritise this.
	 */
	if (!list_empty(&current->ipi_list_node)) {
		list = &current->ipi_list_node;
	} else {
		/*
		 * If the current cpu doesn't have a pending IPI check other
		 * vcpus on the current CPU.
		 */
		list = &current->cpu->pending_ipis;

		if (list_empty(list)) {
			target_vcpu = NULL;
			goto out;
		}

		/*
		 * The list is circular, the root element does not belong to a
		 * vCPU but is used to track if the list is empty and if not
		 * point to the first vCPU with a pending IPI.
		 */
		list = list->next;
	}

	/*
	 * The next vCPU with a pending IPI has been retrieved to be handled
	 * so remove it from the list.
	 */
	list_remove(list);
	target_vcpu = CONTAINER_OF(list, struct vcpu, ipi_list_node);

out:
	sl_unlock(&current->cpu->lock);
	return target_vcpu;
}

/**
 * Send and record the IPI for the target vCPU.
 */
void hf_ipi_send_interrupt(struct vm *vm, ffa_vcpu_index_t target_vcpu_index)
{
	struct vcpu *target_vcpu = vm_get_vcpu(vm, target_vcpu_index);
	struct cpu *target_cpu = target_vcpu->cpu;

	sl_lock(&target_cpu->lock);
	/*
	 * Since vCPUs are pinned to a physical cpu they can only belong
	 * to one list. Therefore check if the vCPU is in a list. If not
	 * add it and send the IPI SGI.
	 */
	if (list_empty(&target_vcpu->ipi_list_node)) {
		list_prepend(&target_cpu->pending_ipis,
			     &target_vcpu->ipi_list_node);

		plat_interrupts_send_sgi(HF_IPI_INTID, target_cpu, true);
	}

	sl_unlock(&target_cpu->lock);
}

/**
 * Enum to track the next SRI action that should be performed for an IPI to
 * a vCPU in the WAITING state.
 */
enum ipi_sri_action {
	/* First entry into the handling function. */
	IPI_SRI_ACTION_INIT,
	/* For a waiting state trigger and SRI not delayed. */
	IPI_SRI_ACTION_NOT_DELAYED,
	/*
	 * For a waiting state set delayed SRI to prioritize a running vCPU,
	 * preventing the running vCPU becoming preempted.
	 */
	IPI_SRI_ACTION_DELAYED,
	/* SRI already set. */
	IPI_SRI_ACTION_NONE,
};

/**
 * IPI IRQ handling for each vCPU state, the ipi_sri_action is used to know
 * which SRI action to use when there is a vCPU in the WAITING state.
 * Elements of the list of vCPUs on the CPU with pending IPIs will be traversed
 * and depending of the state of each, the handling specific to IPIs will be
 * taken:
 *   - RUNNING: Set the ipi_sri_action to IPI_SRI_ACTION_DELAYED, so if an SRI
 *     is required for a different vCPU, the running (current) vCPU will still
 *     handle the IPI. Return false so that the normal secure interrupt handling
 *     continues.
 *   - WAITING: If the ipi_sri_action is IPI_SRI_ACTION_NONE, an SRI has either
 *     already been triggered or set to delayed so we don't need to do anything.
 *     Otherwise:
 *      - If the running vCPU has a pending IPI, the ipi_sri_action will be
 *        IPI_SRI_ACTION_DELAYED so set the SRI to delayed, this means the SRI
 *        will be triggered on the next world switch to NWd and the running
 *        vCPU will not be stopped before it has handled it's IPI. Set the
 *        ipi_sri_action to IPI_SRI_ACTION_NONE, as we only need to set the
 *        SRI once.
 *      - If the running vCPU does not have a pending IPI, the ipi_sri_action
 *        will either be IPI_SRI_ACTION_INIT, if we are in the head of the list,
 *        or IPI_SRI_ACTION_NOT_DELAYED, in these cases we want to trigger the
 *        SRI immediately, so the NWd can schedule the target vCPU to handle
 *        the IPI. Set the ipi_sri_action to IPI_SRI_ACTION_NONE as we only need
 *        to trigger the SRI once.
 *   - PREEMPTED/BLOCKED:
 *     - If it's the head of the list (indicated by
 *       IPI_SRI_ACTION_INIT), return false and allow normal secure interrupt
 *       handling to handle the interrupt as usual.
 *     - Otherwise queue the interrupt for the vCPU.
 * Returns True if the IPI SGI has been fully handled.
 * False if further secure interrupt handling is required, this will
 * only be the case for the target vCPU head of the pending ipi list, if it
 * is in the RUNNING, PREEMPTED or BLOCKED state.
 */
static bool hf_ipi_handle_list_element(struct vcpu_locked target_vcpu_locked,
				       enum ipi_sri_action *ipi_sri_action)
{
	bool ret = true;
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;

	assert(ipi_sri_action != NULL);

	vcpu_virt_interrupt_inject(target_vcpu_locked, HF_IPI_INTID);

	switch (target_vcpu->state) {
	case VCPU_STATE_RUNNING:
		if (*ipi_sri_action != IPI_SRI_ACTION_INIT) {
			panic("%s: If present the RUNNING vCPU should be the "
			      "first to be handled.\n",
			      __func__);
		}
		/*
		 * Any SRI should be delayed to prioritize the running vCPU,
		 * preventing it from entering the PREEMPTED state by the SRI
		 * before the IPI is handled.
		 */
		*ipi_sri_action = IPI_SRI_ACTION_DELAYED;
		ret = false;
		break;
	case VCPU_STATE_WAITING:
		if (*ipi_sri_action == IPI_SRI_ACTION_INIT ||
		    *ipi_sri_action == IPI_SRI_ACTION_NOT_DELAYED) {
			/*
			 * The current target vCPU is either the first element
			 * in the pending list or there is not running vCPU in
			 * the list, so we are ok to trigger the SRI
			 * immediately.
			 */
			ffa_notifications_sri_trigger_not_delayed(
				target_vcpu->cpu);
		} else if (*ipi_sri_action == IPI_SRI_ACTION_DELAYED) {
			/*
			 * Otherwise a running vCPU has a pending IPI so set a
			 * delayed SRI, so as not to preempt the running vCPU
			 * before it is able to handle it's IPI.
			 */
			ffa_notifications_sri_set_delayed(target_vcpu->cpu);
		}
		*ipi_sri_action = IPI_SRI_ACTION_NONE;
		break;
	case VCPU_STATE_BLOCKED:
	case VCPU_STATE_PREEMPTED:
		if (*ipi_sri_action == IPI_SRI_ACTION_INIT) {
			/*
			 * The current target vCPU is the top of the list of
			 * pending IPIs so allow it to be handled by the default
			 * secure interrupt handling. Change the state to
			 * IPI_SRI_ACTION_NOT_DELAYED since there now can't be
			 * any running vCPUs with pending IPIs (it would have
			 * been the head of the list) so we are safe to trigger
			 * the SRI for any waiting vCPUs immediately.
			 */
			*ipi_sri_action = IPI_SRI_ACTION_NOT_DELAYED;
			ret = false;
		}
		break;
	default:
		dlog_error(
			"%s: unexpected state: %u handling an IPI for [%x %u]",
			__func__, target_vcpu->state, target_vcpu->vm->id,
			vcpu_index(target_vcpu));
	}

	return ret;
}

/**
 * IPI IRQ specific handling for the secure interrupt.
 */
bool hf_ipi_handle(struct vcpu_locked target_vcpu_locked)
{
	enum ipi_sri_action ipi_sri_action = IPI_SRI_ACTION_INIT;
	bool ret = true;
	struct vcpu *current = target_vcpu_locked.vcpu;

	ret = hf_ipi_handle_list_element(target_vcpu_locked, &ipi_sri_action);

	/*
	 * Clear the pending ipi list, handling the ipi for the remaining
	 * target vCPUs.
	 */
	for (struct vcpu *target_vcpu = hf_ipi_get_pending_target_vcpu(current);
	     target_vcpu != NULL;
	     target_vcpu = hf_ipi_get_pending_target_vcpu(target_vcpu)) {
		if (target_vcpu != current) {
			target_vcpu_locked = vcpu_lock(target_vcpu);
		}

		hf_ipi_handle_list_element(target_vcpu_locked, &ipi_sri_action);
		if (target_vcpu != current) {
			vcpu_unlock(&target_vcpu_locked);
		}
	}

	return ret;
}
