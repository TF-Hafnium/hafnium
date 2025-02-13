/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/interrupts.h"

#include "hf/arch/gicv3.h"
#include "hf/arch/host_timer.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/ffa/direct_messaging.h"
#include "hf/ffa/vm.h"
#include "hf/hf_ipi.h"
#include "hf/vm.h"

/**
 * Drops the current interrupt priority and deactivate the given interrupt ID
 * for the calling vCPU.
 *
 * Returns 0 on success, or -1 otherwise.
 */
int64_t ffa_interrupts_deactivate(uint32_t pint_id, uint32_t vint_id,
				  struct vcpu *current)
{
	struct vcpu_locked current_locked;
	uint32_t int_id;
	int ret = 0;

	current_locked = vcpu_lock(current);
	if (vint_id >= HF_NUM_INTIDS) {
		ret = -1;
		goto out;
	}

	/*
	 * Current implementation maps virtual interrupt to physical interrupt.
	 */
	if (pint_id != vint_id) {
		ret = -1;
		goto out;
	}

	/*
	 * A malicious SP could de-activate an interrupt that does not belong to
	 * it. Return error to indicate failure.
	 */
	if (!vcpu_interrupt_queue_peek(current_locked, &int_id)) {
		dlog_error("No virtual interrupt to be deactivated\n");
		ret = -1;
		goto out;
	}

	if (int_id != vint_id) {
		dlog_error("Unknown interrupt being deactivated %u\n", vint_id);
		ret = -1;
		goto out;
	}

	if (current->requires_deactivate_call) {
		/* There is no preempted vCPU to resume. */
		assert(current->preempted_vcpu == NULL);

		vcpu_secure_interrupt_complete(current_locked);
	}

	/*
	 * Now that the virtual interrupt has been serviced and deactivated,
	 * remove it from the queue, if it was pending.
	 */
	vcpu_interrupt_queue_pop(current_locked, &int_id);
	assert(vint_id == int_id);
out:
	vcpu_unlock(&current_locked);
	return ret;
}

static struct vcpu *ffa_interrupts_find_target_vcpu_secure_interrupt(
	struct vcpu *current, uint32_t interrupt_id)
{
	/*
	 * Find which VM/SP owns this interrupt. We then find the
	 * corresponding vCPU context for this CPU.
	 */
	for (ffa_vm_count_t index = 0; index < vm_get_count(); ++index) {
		struct vm *vm = vm_find_index(index);

		for (uint32_t j = 0; j < HF_NUM_INTIDS; j++) {
			struct interrupt_descriptor int_desc =
				vm->interrupt_desc[j];

			/*
			 * Interrupt descriptors are populated
			 * contiguously.
			 */
			if (!int_desc.valid) {
				break;
			}
			if (int_desc.interrupt_id == interrupt_id) {
				return api_ffa_get_vm_vcpu(vm, current);
			}
		}
	}

	return NULL;
}

static struct vcpu *ffa_interrupts_find_target_vcpu(struct vcpu *current,
						    uint32_t interrupt_id)
{
	struct vcpu *target_vcpu;

	switch (interrupt_id) {
	case HF_IPI_INTID:
		/*
		 * Get the next vCPU with a pending IPI. If all vCPUs
		 * have had their IPIs handled this will return NULL.
		 */
		target_vcpu = hf_ipi_get_pending_target_vcpu(current);
		break;
	case ARM_EL1_VIRT_TIMER_PHYS_INT:
		/* Fall through */
	case ARM_EL1_PHYS_TIMER_PHYS_INT:
		panic("Timer interrupt not expected to fire: %u\n",
		      interrupt_id);
	default:
		target_vcpu = ffa_interrupts_find_target_vcpu_secure_interrupt(
			current, interrupt_id);

		/* The target vCPU for a secure interrupt cannot be NULL. */
		CHECK(target_vcpu != NULL);
	}

	return target_vcpu;
}

/*
 * Queue the pending virtual interrupt for target vcpu. Necessary fields
 * tracking the secure interrupt processing are set accordingly.
 */
static void ffa_interrupts_queue_vint(struct vcpu_locked target_vcpu_locked,
				      uint32_t vint_id,
				      struct vcpu_locked current_locked)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct vcpu *preempted_vcpu = current_locked.vcpu;

	if (preempted_vcpu != NULL) {
		target_vcpu->preempted_vcpu = preempted_vcpu;
		preempted_vcpu->state = VCPU_STATE_PREEMPTED;
	}

	/* Queue the pending virtual interrupt for target vcpu. */
	if (!vcpu_interrupt_queue_push(target_vcpu_locked, vint_id)) {
		panic("Exhausted interrupt queue for vcpu of SP: %x\n",
		      target_vcpu->vm->id);
	}
}

/**
 * If the interrupts were indeed masked by SPMC before an SP's vCPU was resumed,
 * restore the priority mask thereby allowing the interrupts to be delivered.
 */
void ffa_interrupts_unmask(struct vcpu *current)
{
	plat_interrupts_set_priority_mask(current->prev_interrupt_priority);
}

/**
 * Enforce action of an SP in response to non-secure or other-secure interrupt
 * by changing the priority mask. Effectively, physical interrupts shall not
 * trigger which has the same effect as queueing interrupts.
 */
void ffa_interrupts_mask(struct vcpu_locked receiver_vcpu_locked)
{
	struct vcpu *receiver_vcpu = receiver_vcpu_locked.vcpu;
	uint8_t current_priority;

	/* Save current value of priority mask. */
	current_priority = plat_interrupts_get_priority_mask();
	receiver_vcpu->prev_interrupt_priority = current_priority;

	if (receiver_vcpu->vm->other_s_interrupts_action ==
		    OTHER_S_INT_ACTION_QUEUED ||
	    receiver_vcpu->scheduling_mode == SPMC_MODE) {
		/*
		 * If secure interrupts not masked yet, mask them now. We could
		 * enter SPMC scheduled mode when an EL3 SPMD Logical partition
		 * sends a direct request, and we are making the IMPDEF choice
		 * to mask interrupts when such a situation occurs. This keeps
		 * design simple.
		 */
		if (current_priority > SWD_MASK_ALL_INT) {
			plat_interrupts_set_priority_mask(SWD_MASK_ALL_INT);
		}
	} else if (receiver_vcpu->vm->ns_interrupts_action ==
		   NS_ACTION_QUEUED) {
		/* If non secure interrupts not masked yet, mask them now. */
		if (current_priority > SWD_MASK_NS_INT) {
			plat_interrupts_set_priority_mask(SWD_MASK_NS_INT);
		}
	}
}

/**
 * Handles the secure interrupt according to the target vCPU's state
 * in the case the owner of the interrupt is an S-EL0 partition.
 */
static struct vcpu *ffa_interrupts_signal_secure_interrupt_sel0(
	struct vcpu_locked current_locked,
	struct vcpu_locked target_vcpu_locked, uint32_t v_intid)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct vcpu *next;

	/* Secure interrupt signaling and queuing for S-EL0 SP. */
	switch (target_vcpu->state) {
	case VCPU_STATE_WAITING: {
		struct ffa_value ret_interrupt =
			api_ffa_interrupt_return(v_intid);

		/* FF-A v1.1 EAC0 Table 8.1 case 1 and Table 12.10. */
		dlog_verbose("S-EL0: Secure interrupt signaled: %x\n",
			     target_vcpu->vm->id);

		vcpu_enter_secure_interrupt_rtm(target_vcpu_locked);
		ffa_interrupts_mask(target_vcpu_locked);

		vcpu_set_running(target_vcpu_locked, &ret_interrupt);

		/*
		 * If the execution was in NWd as well, set the vCPU
		 * in preempted state as well.
		 */
		ffa_interrupts_queue_vint(target_vcpu_locked, v_intid,
					  current_locked);

		/*
		 * The target vcpu could have migrated to a different physical
		 * CPU. SPMC will migrate it to current physical CPU and resume
		 * it.
		 */
		target_vcpu->cpu = current_locked.vcpu->cpu;

		/* Switch to target vCPU responsible for this interrupt. */
		next = target_vcpu;
		break;
	}
	case VCPU_STATE_BLOCKED:
	case VCPU_STATE_PREEMPTED:
	case VCPU_STATE_RUNNING:
		dlog_verbose("S-EL0: Secure interrupt queued: %x\n",
			     target_vcpu->vm->id);
		/*
		 * The target vCPU cannot be resumed, SPMC resumes current
		 * vCPU.
		 */
		next = NULL;
		ffa_interrupts_queue_vint(target_vcpu_locked, v_intid,
					  (struct vcpu_locked){.vcpu = NULL});
		break;
	default:
		panic("Secure interrupt cannot be signaled to target SP\n");
		break;
	}

	return next;
}

/**
 * Handles the secure interrupt according to the target vCPU's state
 * in the case the owner of the interrupt is an S-EL1 partition.
 */
static struct vcpu *ffa_interrupts_signal_secure_interrupt_sel1(
	struct vcpu_locked current_locked,
	struct vcpu_locked target_vcpu_locked, uint32_t v_intid)
{
	struct vcpu *target_vcpu = target_vcpu_locked.vcpu;
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *next = NULL;

	/* Secure interrupt signaling and queuing for S-EL1 SP. */
	switch (target_vcpu->state) {
	case VCPU_STATE_WAITING: {
		struct ffa_value ret_interrupt =
			api_ffa_interrupt_return(v_intid);

		/* FF-A v1.1 EAC0 Table 8.2 case 1 and Table 12.10. */
		vcpu_enter_secure_interrupt_rtm(target_vcpu_locked);
		ffa_interrupts_mask(target_vcpu_locked);

		/*
		 * Ideally, we have to mask non-secure interrupts here
		 * since the spec mandates that SPMC should make sure
		 * SPMC scheduled call chain cannot be preempted by a
		 * non-secure interrupt. However, our current design
		 * takes care of it implicitly.
		 */
		vcpu_set_running(target_vcpu_locked, &ret_interrupt);

		ffa_interrupts_queue_vint(target_vcpu_locked, v_intid,
					  current_locked);
		next = target_vcpu;

		if (target_vcpu->cpu != current_locked.vcpu->cpu) {
			/*
			 * The target vcpu could have migrated to a different
			 * physical CPU. SPMC will migrate it to current
			 * physical CPU and resume it.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
			target_vcpu->cpu = current_locked.vcpu->cpu;
		}
		break;
	}
	case VCPU_STATE_BLOCKED:
		if (target_vcpu->cpu != current_locked.vcpu->cpu) {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
			next = NULL;
			ffa_interrupts_queue_vint(
				target_vcpu_locked, v_intid,
				(struct vcpu_locked){.vcpu = NULL});
		} else if (ffa_direct_msg_precedes_in_call_chain(
				   current_locked, target_vcpu_locked)) {
			struct ffa_value ret_interrupt =
				api_ffa_interrupt_return(0);

			/*
			 * If the target vCPU ran earlier in the same call
			 * chain as the current vCPU, SPMC leaves all
			 * intermediate execution contexts in blocked state and
			 * resumes the target vCPU for handling secure
			 * interrupt.
			 * Under the current design, there is only one possible
			 * scenario in which this could happen: both the
			 * preempted (i.e. current) and target vCPU are in the
			 * same NWd scheduled call chain and is described in the
			 * Scenario 1 of Table 8.4 in EAC0 spec.
			 */
			assert(current_locked.vcpu->scheduling_mode ==
			       NWD_MODE);
			assert(target_vcpu->scheduling_mode == NWD_MODE);

			/*
			 * The execution preempted the call chain that involved
			 * the targeted and the current SPs.
			 * The targetted SP is set running, whilst the
			 * preempted SP is set PREEMPTED.
			 */
			vcpu_set_running(target_vcpu_locked, &ret_interrupt);

			ffa_interrupts_queue_vint(target_vcpu_locked, v_intid,
						  current_locked);

			next = target_vcpu;
		} else {
			/*
			 * The target vCPU cannot be resumed now because it is
			 * in BLOCKED state (it yielded CPU cycles using
			 * FFA_YIELD). SPMC queues the virtual interrupt and
			 * resumes the current vCPU which could belong to either
			 * a VM or a SP.
			 */
			next = NULL;
			ffa_interrupts_queue_vint(
				target_vcpu_locked, v_intid,
				(struct vcpu_locked){.vcpu = NULL});
		}
		break;
	case VCPU_STATE_PREEMPTED:
		if (target_vcpu->cpu == current_locked.vcpu->cpu) {
			/*
			 * We do not resume a target vCPU that has been already
			 * pre-empted by an interrupt. Make the vIRQ pending for
			 * target SP(i.e., queue the interrupt) and continue to
			 * resume current vCPU. Refer to section 8.3.2.1 bullet
			 * 3 in the FF-A v1.1 EAC0 spec.
			 */

			if (current->vm->id == HF_OTHER_WORLD_ID) {
				/*
				 * The target vCPU must have been preempted by a
				 * non secure interrupt. It could not have been
				 * preempted by a secure interrupt as current
				 * SPMC implementation does not allow secure
				 * interrupt prioritization. Moreover, the
				 * target vCPU should have been in Normal World
				 * scheduled mode as SPMC scheduled mode call
				 * chain cannot be preempted by a non secure
				 * interrupt.
				 */
				CHECK(target_vcpu->scheduling_mode == NWD_MODE);
			}
		} else {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
		}

		next = NULL;
		ffa_interrupts_queue_vint(target_vcpu_locked, v_intid,
					  (struct vcpu_locked){.vcpu = NULL});

		break;
	case VCPU_STATE_RUNNING:
		if (current == target_vcpu) {
			/*
			 * This is the special scenario where the current
			 * running execution context also happens to be the
			 * target of the secure interrupt. In this case, it
			 * needs to signal completion of secure interrupt
			 * implicitly. Refer to the embedded comment in vcpu.h
			 * file for the description of this variable.
			 */

			current->requires_deactivate_call = true;
		} else {
			/*
			 * The target vcpu has migrated to a different physical
			 * CPU. Hence, it cannot be resumed on this CPU, SPMC
			 * resumes current vCPU.
			 */
			assert(target_vcpu->vm->vcpu_count == 1);
		}
		next = NULL;
		ffa_interrupts_queue_vint(target_vcpu_locked, v_intid,
					  (struct vcpu_locked){.vcpu = NULL});
		break;
	case VCPU_STATE_BLOCKED_INTERRUPT:
		/* WFI is no-op for SP. Fall through. */
	default:
		/*
		 * vCPU of Target SP cannot be in OFF/ABORTED state if it has
		 * to handle secure interrupt.
		 */
		panic("Secure interrupt cannot be signaled to target SP\n");
		break;
	}

	return next;
}

/**
 * Obtain the physical interrupt that triggered from the interrupt controller,
 * and inject the corresponding virtual interrupt to the target vCPU.
 * When PEs executing in the Normal World, and secure interrupts trigger,
 * execution is trapped into EL3. SPMD then routes the interrupt to SPMC
 * through FFA_INTERRUPT_32 ABI synchronously using eret conduit.
 */
void ffa_interrupts_handle_secure_interrupt(struct vcpu *current,
					    struct vcpu **next)
{
	struct vcpu *target_vcpu;
	struct vcpu_locked target_vcpu_locked =
		(struct vcpu_locked){.vcpu = NULL};
	struct vcpu_locked current_locked;
	uint32_t intid;
	struct vm_locked target_vm_locked;
	uint32_t v_intid;

	/* Find pending interrupt id. This also activates the interrupt. */
	intid = plat_interrupts_get_pending_interrupt_id();
	v_intid = intid;

	switch (intid) {
	case ARM_SEL2_TIMER_PHYS_INT:
		/* Disable the S-EL2 physical timer */
		host_timer_disable();
		target_vcpu = timer_find_target_vcpu(current);

		if (target_vcpu != NULL) {
			v_intid = HF_VIRTUAL_TIMER_INTID;
			break;
		}
		/*
		 * It is possible for target_vcpu to be NULL in case of spurious
		 * timer interrupt. Fall through.
		 */
	case SPURIOUS_INTID_OTHER_WORLD:
		/*
		 * Spurious interrupt ID indicating that there are no pending
		 * interrupts to acknowledge. For such scenarios, resume the
		 * current vCPU.
		 */
		*next = NULL;
		return;
	default:
		target_vcpu = ffa_interrupts_find_target_vcpu(current, intid);
		break;
	}

	/*
	 * End the interrupt to drop the running priority. It also deactivates
	 * the physical interrupt. If not, the interrupt could trigger again
	 * after resuming current vCPU.
	 */
	plat_interrupts_end_of_interrupt(intid);

	if (target_vcpu == NULL) {
		/* No further handling required. Resume the current vCPU. */
		*next = NULL;
		return;
	}

	target_vm_locked = vm_lock(target_vcpu->vm);

	if (target_vcpu == current) {
		current_locked = vcpu_lock(current);
		target_vcpu_locked = current_locked;
	} else {
		struct two_vcpu_locked vcpus_locked;
		/* Lock both vCPUs at once to avoid deadlock. */
		vcpus_locked = vcpu_lock_both(current, target_vcpu);
		current_locked = vcpus_locked.vcpu1;
		target_vcpu_locked = vcpus_locked.vcpu2;
	}

	/*
	 * A race condition can occur with the execution contexts belonging to
	 * an MP SP. An interrupt targeting the execution context on present
	 * core can trigger while the execution context of this SP on a
	 * different core is being aborted. In such scenario, the physical
	 * interrupts beloning to the aborted SP are disabled and the current
	 * execution context is resumed.
	 */
	if (target_vcpu->state == VCPU_STATE_ABORTED ||
	    atomic_load_explicit(&target_vcpu->vm->aborting,
				 memory_order_relaxed)) {
		/* Clear fields corresponding to secure interrupt handling. */
		vcpu_secure_interrupt_complete(target_vcpu_locked);
		ffa_vm_disable_interrupts(target_vm_locked);

		/* Resume current vCPU. */
		*next = NULL;
	} else {
		/*
		 * SPMC has started handling a secure interrupt with a clean
		 * slate. This signal should be false unless there was a bug in
		 * source code. Hence, use assert rather than CHECK.
		 */
		assert(!target_vcpu->requires_deactivate_call);

		/* Set the interrupt pending in the target vCPU. */
		vcpu_interrupt_inject(target_vcpu_locked, v_intid);

		switch (intid) {
		case HF_IPI_INTID:
			if (hf_ipi_handle(target_vcpu_locked)) {
				*next = NULL;
				break;
			}
			/*
			 * Fall through in the case handling has not been fully
			 * completed.
			 */
		default:
			/*
			 * Either invoke the handler related to partitions from
			 * S-EL0 or from S-EL1.
			 */
			*next = target_vcpu_locked.vcpu->vm->el0_partition
					? ffa_interrupts_signal_secure_interrupt_sel0(
						  current_locked,
						  target_vcpu_locked, v_intid)
					: ffa_interrupts_signal_secure_interrupt_sel1(
						  current_locked,
						  target_vcpu_locked, v_intid);
		}
	}

	if (target_vcpu_locked.vcpu != NULL) {
		vcpu_unlock(&target_vcpu_locked);
	}

	vcpu_unlock(&current_locked);
	vm_unlock(&target_vm_locked);
}

bool ffa_interrupts_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vcpu_locked current_locked,
	struct vm_locked receiver_locked)
{
	struct vm *next_vm = target_locked.vcpu->vm;
	bool ret = false;

	/*
	 * Inject the NPI if:
	 * - The targeted VM ID is from this world (i.e. if it is an SP).
	 * - The partition has global pending notifications and an NPI hasn't
	 * been injected yet.
	 * - There are pending per-vCPU notifications in the next vCPU.
	 */
	if (vm_id_is_current_world(next_vm->id) &&
	    (vm_are_per_vcpu_notifications_pending(
		     receiver_locked, vcpu_index(target_locked.vcpu)) ||
	     (vm_are_global_notifications_pending(receiver_locked) &&
	      !vm_notifications_is_npi_injected(receiver_locked)))) {
		api_interrupt_inject_locked(target_locked,
					    HF_NOTIFICATION_PENDING_INTID,
					    current_locked, NULL);
		vm_notifications_set_npi_injected(receiver_locked, true);
		ret = true;
	}

	return ret;
}

struct vcpu *ffa_interrupts_unwind_nwd_call_chain(struct vcpu *current_vcpu)
{
	struct vcpu *next;
	struct two_vcpu_locked both_vcpu_locked;

	/*
	 * The action specified by SP in its manifest is ``Non-secure interrupt
	 * is signaled``. Refer to section 8.2.4 rules and guidelines bullet 4.
	 * Hence, the call chain starts unwinding. The current vCPU must have
	 * been a part of NWd scheduled call chain. Therefore, it is pre-empted
	 * and execution is either handed back to the normal world or to the
	 * previous SP vCPU in the call chain through the FFA_INTERRUPT ABI.
	 * The api_preempt() call is equivalent to calling
	 * api_switch_to_other_world for current vCPU passing FFA_INTERRUPT. The
	 * SP can be resumed later by FFA_RUN.
	 */
	CHECK(current_vcpu->scheduling_mode == NWD_MODE);
	assert(current_vcpu->call_chain.next_node == NULL);

	if (current_vcpu->call_chain.prev_node == NULL) {
		/* End of NWd scheduled call chain */
		return api_preempt(current_vcpu);
	}

	next = current_vcpu->call_chain.prev_node;
	CHECK(next != NULL);

	/*
	 * Lock both vCPUs. Strictly speaking, it may not be necessary since
	 * next is guaranteed to be in BLOCKED state as it is the predecessor of
	 * the current vCPU in the present call chain.
	 */
	both_vcpu_locked = vcpu_lock_both(current_vcpu, next);

	/* Removing a node from an existing call chain. */
	current_vcpu->call_chain.prev_node = NULL;
	current_vcpu->state = VCPU_STATE_PREEMPTED;

	/*
	 * SPMC applies the runtime model till when the vCPU transitions from
	 * running to waiting state. Moreover, the SP continues to remain in
	 * its CPU cycle allocation mode. Hence, rt_model and scheduling_mode
	 * are not changed here.
	 */
	assert(next->state == VCPU_STATE_BLOCKED);
	assert(next->call_chain.next_node == current_vcpu);

	next->call_chain.next_node = NULL;

	vcpu_set_running(both_vcpu_locked.vcpu2,
			 &(struct ffa_value){
				 .func = FFA_INTERRUPT_32,
				 .arg1 = ffa_vm_vcpu(current_vcpu->vm->id,
						     vcpu_index(current_vcpu)),
			 });

	sl_unlock(&next->lock);
	sl_unlock(&current_vcpu->lock);

	return next;
}

static void ffa_interrupts_enable_virtual_maintenance_interrupts(
	struct vcpu_locked current_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;
	struct vm *vm;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;
	vm = current->vm;

	if (ffa_vm_managed_exit_supported(vm)) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_MANAGED_EXIT_INTID);
		/*
		 * SPMC decides the interrupt type for Managed exit signal based
		 * on the partition manifest.
		 */
		if (vm->me_signal_virq) {
			vcpu_virt_interrupt_set_type(interrupts,
						     HF_MANAGED_EXIT_INTID,
						     INTERRUPT_TYPE_IRQ);
		} else {
			vcpu_virt_interrupt_set_type(interrupts,
						     HF_MANAGED_EXIT_INTID,
						     INTERRUPT_TYPE_FIQ);
		}
	}

	if (vm->notifications.enabled) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_NOTIFICATION_PENDING_INTID);
	}
}

/**
 * Enable relevant virtual interrupts for Secure Partitions.
 * For all SPs, any applicable virtual maintenance interrupts are enabled.
 * Additionally, for S-EL0 partitions, all the interrupts declared in the
 * partition manifest are enabled at the virtual interrupt controller
 * interface early during the boot stage as an S-EL0 SP need not call
 * HF_INTERRUPT_ENABLE hypervisor ABI explicitly.
 */
void ffa_interrupts_enable_virtual_interrupts(struct vcpu_locked current_locked,
					      struct vm_locked vm_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;
	struct vm *vm;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;
	vm = current->vm;
	assert(vm == vm_locked.vm);

	if (vm->el0_partition) {
		for (uint32_t k = 0; k < VM_MANIFEST_MAX_INTERRUPTS; k++) {
			struct interrupt_descriptor int_desc;

			int_desc = vm_locked.vm->interrupt_desc[k];

			/* Interrupt descriptors are populated contiguously. */
			if (!int_desc.valid) {
				break;
			}
			vcpu_virt_interrupt_set_enabled(interrupts,
							int_desc.interrupt_id);
		}
	}

	ffa_interrupts_enable_virtual_maintenance_interrupts(current_locked);
}

/**
 * Reconfigure the interrupt belonging to the current partition at runtime.
 * At present, this paravirtualized interface only allows the following
 * commands which signify what change is being requested by the current
 * partition:
 * - Change the target CPU of the interrupt.
 * - Change the security state of the interrupt.
 * - Enable or disable the physical interrupt.
 */
int64_t ffa_interrupts_reconfigure(uint32_t int_id, uint32_t command,
				   uint32_t value, struct vcpu *current)
{
	struct vm *vm = current->vm;
	struct vm_locked vm_locked;
	int64_t ret = -1;
	struct interrupt_descriptor *int_desc = NULL;

	/*
	 * Lock VM to protect interrupt descriptor from being modified
	 * concurrently.
	 */
	vm_locked = vm_lock(vm);

	switch (command) {
	case INT_RECONFIGURE_TARGET_PE:
		/* Here, value represents the target PE index. */
		if (value >= MAX_CPUS) {
			dlog_verbose(
				"Illegal target PE index specified while "
				"reconfiguring interrupt %x\n",
				int_id);
			goto out_unlock;
		}

		/*
		 * An UP SP cannot reconfigure an interrupt to be targetted to
		 * any other physical CPU except the one it is currently
		 * running on.
		 */
		if (vm_is_up(vm) && value != cpu_index(current->cpu)) {
			dlog_verbose(
				"Illegal target PE index specified by current "
				"UP SP\n");
			goto out_unlock;
		}

		/* Configure the interrupt to be routed to a specific CPU. */
		int_desc = vm_interrupt_set_target_mpidr(
			vm_locked, int_id, cpu_find_index(value)->id);
		break;
	case INT_RECONFIGURE_SEC_STATE:
		/* Specify the new security state of the interrupt. */
		if (value != INT_DESC_SEC_STATE_NS &&
		    value != INT_DESC_SEC_STATE_S) {
			dlog_verbose(
				"Illegal value %x specified while "
				"reconfiguring interrupt %x\n",
				value, int_id);
			goto out_unlock;
		}
		int_desc = vm_interrupt_set_sec_state(vm_locked, int_id, value);
		break;
	case INT_RECONFIGURE_ENABLE:
		/* Enable or disable the interrupt. */
		if (value != INT_DISABLE && value != INT_ENABLE) {
			dlog_verbose(
				"Illegal value %x specified while "
				"reconfiguring interrupt %x\n",
				value, int_id);
			goto out_unlock;
		} else {
			int_desc = vm_interrupt_set_enable(vm_locked, int_id,
							   value == INT_ENABLE);
		}
		break;
	default:
		dlog_verbose("Interrupt reconfigure: Unsupported command %x\n",
			     command);
		goto out_unlock;
	}

	/* Check if the interrupt belongs to the current SP. */
	if (int_desc == NULL) {
		dlog_verbose("Interrupt %x does not belong to current SP\n",
			     int_id);
		goto out_unlock;
	}

	ret = 0;
	plat_interrupts_reconfigure_interrupt(*int_desc);

out_unlock:
	vm_unlock(&vm_locked);

	return ret;
}

/* Returns the virtual interrupt id to be handled by SP. */
uint32_t ffa_interrupts_get(struct vcpu_locked current_locked)
{
	uint32_t int_id;

	/*
	 * If there are any virtual interrupts in the queue, return the first
	 * entry. Else, return the pending interrupt from the bitmap.
	 */
	if (vcpu_interrupt_queue_peek(current_locked, &int_id)) {
		struct interrupts *interrupts;

		/*
		 * Mark the virtual interrupt as no longer pending and decrement
		 * the count.
		 */
		interrupts = &current_locked.vcpu->interrupts;
		vcpu_virt_interrupt_clear_pending(interrupts, int_id);
		vcpu_interrupt_count_decrement(current_locked, interrupts,
					       int_id);

		return int_id;
	}

	return api_interrupt_get(current_locked);
}

/**
 * Run the vCPU in SPMC schedule mode under the runtime model for secure
 * interrupt handling.
 */
static void ffa_interrupts_run_in_sec_interrupt_rtm(
	struct vcpu_locked target_vcpu_locked)
{
	struct vcpu *target_vcpu;

	target_vcpu = target_vcpu_locked.vcpu;

	/* Mark the registers as unavailable now. */
	target_vcpu->regs_available = false;
	target_vcpu->scheduling_mode = SPMC_MODE;
	target_vcpu->rt_model = RTM_SEC_INTERRUPT;
	target_vcpu->state = VCPU_STATE_RUNNING;
	target_vcpu->requires_deactivate_call = false;
}

bool ffa_interrupts_intercept_call(struct vcpu_locked current_locked,
				   struct vcpu_locked next_locked,
				   struct ffa_value *signal_interrupt)
{
	uint32_t intid;

	/*
	 * Check if there are any pending virtual secure interrupts to be
	 * handled.
	 */
	if (vcpu_interrupt_queue_peek(current_locked, &intid)) {
		/*
		 * Prepare to signal virtual secure interrupt to S-EL0/S-EL1 SP
		 * in WAITING state. Refer to FF-A v1.2 Table 9.1 and Table 9.2
		 * case 1.
		 */
		*signal_interrupt = api_ffa_interrupt_return(intid);

		/*
		 * Prepare to resume this partition's vCPU in SPMC
		 * schedule mode to handle virtual secure interrupt.
		 */
		ffa_interrupts_run_in_sec_interrupt_rtm(current_locked);

		current_locked.vcpu->preempted_vcpu = next_locked.vcpu;
		next_locked.vcpu->state = VCPU_STATE_PREEMPTED;

		dlog_verbose("%s: Pending interrup, intercepting FF-A call.\n",
			     __func__);

		return true;
	}

	return false;
}
