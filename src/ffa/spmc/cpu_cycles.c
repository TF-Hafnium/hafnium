/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/gicv3.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/ffa/interrupts.h"
#include "hf/plat/interrupts.h"
#include "hf/vm.h"

void plat_ffa_vcpu_allow_interrupts(struct vcpu *current);
bool sp_boot_next(struct vcpu_locked current_locked, struct vcpu **next);

bool ffa_cpu_cycles_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
				struct ffa_value *ret)
{
	(void)vm_id;
	(void)vcpu_idx;
	(void)ret;

	return false;
}

/**
 * Check if current VM can resume target VM using FFA_RUN ABI.
 */
bool ffa_cpu_cycles_run_checks(struct vcpu_locked current_locked,
			       ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			       struct ffa_value *run_ret, struct vcpu **next)
{
	/*
	 * Under the Partition runtime model specified in FF-A v1.1-Beta0 spec,
	 * SP can invoke FFA_RUN to resume target SP.
	 */
	struct vcpu *target_vcpu;
	struct vcpu *current = current_locked.vcpu;
	bool ret = true;
	struct vm *vm;
	struct vcpu_locked target_locked;
	struct two_vcpu_locked vcpus_locked;

	vm = vm_find(target_vm_id);
	if (vm == NULL) {
		return false;
	}

	if (vm_is_mp(vm) && vm_is_mp(current->vm) &&
	    vcpu_idx != cpu_index(current->cpu)) {
		dlog_verbose("vcpu_idx (%d) != pcpu index (%zu)\n", vcpu_idx,
			     cpu_index(current->cpu));
		return false;
	}

	target_vcpu = api_ffa_get_vm_vcpu(vm, current);

	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, target_vcpu);
	current_locked = vcpus_locked.vcpu1;
	target_locked = vcpus_locked.vcpu2;

	/* Only the primary VM can turn ON a vCPU that is currently OFF. */
	if (!vm_is_primary(current->vm) &&
	    target_vcpu->state == VCPU_STATE_OFF) {
		run_ret->arg2 = FFA_DENIED;
		ret = false;
		goto out;
	}

	/*
	 * An SPx can resume another SPy only when SPy is in PREEMPTED or
	 * BLOCKED state.
	 */
	if (vm_id_is_current_world(current->vm->id) &&
	    vm_id_is_current_world(target_vm_id)) {
		/* Target SP must be in preempted or blocked state. */
		if (target_vcpu->state != VCPU_STATE_PREEMPTED &&
		    target_vcpu->state != VCPU_STATE_BLOCKED) {
			run_ret->arg2 = FFA_DENIED;
			ret = false;
			goto out;
		}
	}

	/* A SP cannot invoke FFA_RUN to resume a normal world VM. */
	if (!vm_id_is_current_world(target_vm_id)) {
		run_ret->arg2 = FFA_DENIED;
		ret = false;
		goto out;
	}

	vcpu_secondary_reset_and_start(target_locked, vm->secondary_ep, 0);

	if (vm_id_is_current_world(current->vm->id)) {
		/*
		 * Refer FF-A v1.1 EAC0 spec section 8.3.2.2.1
		 * Signaling an Other S-Int in blocked state
		 */
		if (current->preempted_vcpu != NULL) {
			/*
			 * After the target SP execution context has handled
			 * the interrupt, it uses the FFA_RUN ABI to resume
			 * the request due to which it had entered the blocked
			 * state earlier.
			 * Deny the state transition if the SP didnt perform the
			 * deactivation of the secure virtual interrupt.
			 */
			if (!vcpu_is_interrupt_queue_empty(current_locked)) {
				run_ret->arg2 = FFA_DENIED;
				ret = false;
				goto out;
			}

			/*
			 * Refer Figure 8.13 Scenario 1: Implementation choice:
			 * SPMC left all intermediate SP execution contexts in
			 * blocked state. Hence, SPMC now bypasses the
			 * intermediate these execution contexts and resumes the
			 * SP execution context that was originally preempted.
			 */
			*next = current->preempted_vcpu;
			if (target_vcpu != current->preempted_vcpu) {
				dlog_verbose("Skipping intermediate vCPUs\n");
			}
			/*
			 * This flag should not have been set by SPMC when it
			 * signaled the virtual interrupt to the SP while SP was
			 * in WAITING or BLOCKED states. Refer the embedded
			 * comment in vcpu.h file for further description.
			 */
			assert(!current->requires_deactivate_call);

			/*
			 * Clear fields corresponding to secure interrupt
			 * handling.
			 */
			vcpu_secure_interrupt_complete(current_locked);
		}
	}

	/* Check if a vCPU of SP is being resumed. */
	if (vm_id_is_current_world(target_vm_id)) {
		/*
		 * A call chain cannot span CPUs. The target vCPU can only be
		 * resumed by FFA_RUN on present CPU.
		 */
		if ((target_vcpu->call_chain.prev_node != NULL ||
		     target_vcpu->call_chain.next_node != NULL) &&
		    (target_vcpu->cpu != current->cpu)) {
			run_ret->arg2 = FFA_DENIED;
			ret = false;
			goto out;
		}

		if (!vcpu_is_interrupt_queue_empty(target_locked)) {
			/*
			 * Consider the following scenarios: a secure interrupt
			 * triggered in normal world and is targeted to an SP.
			 * Scenario A): The target SP's vCPU was preempted by a
			 *              non secure interrupt.
			 * Scenario B): The target SP's vCPU was in blocked
			 *              state after it yielded CPU cycles to
			 *              normal world using FFA_YIELD.
			 * In both the scenarios, SPMC would have injected a
			 * virtual interrupt and set the appropriate flags after
			 * de-activating the secure physical interrupt. SPMC did
			 * not resume the target vCPU at that moment.
			 */
			assert(target_vcpu->state == VCPU_STATE_PREEMPTED ||
			       target_vcpu->state == VCPU_STATE_BLOCKED);
			assert(vcpu_interrupt_count_get(target_locked) > 0);

			/*
			 * This check is to ensure the target SP vCPU could
			 * only be a part of NWd scheduled call chain. FF-A v1.1
			 * spec prohibits an SPMC scheduled call chain to be
			 * preempted by a non secure interrupt.
			 */
			CHECK(target_vcpu->scheduling_mode == NWD_MODE);
		}
	}

out:
	vcpu_unlock(&target_locked);
	return ret;
}

/**
 * SPMC scheduled call chain is completely unwound.
 */
static void plat_ffa_exit_spmc_schedule_mode(struct vcpu_locked current_locked)
{
	struct vcpu *current;

	current = current_locked.vcpu;
	assert(current->call_chain.next_node == NULL);
	CHECK(current->scheduling_mode == SPMC_MODE);

	current->scheduling_mode = NONE;
	current->rt_model = RTM_NONE;
}

/**
 * A SP in running state could have been pre-empted by a secure interrupt. SPM
 * would switch the execution to the vCPU of target SP responsible for interupt
 * handling. Upon completion of interrupt handling, vCPU performs interrupt
 * signal completion through FFA_MSG_WAIT ABI (provided it was in waiting state
 * when interrupt was signaled).
 *
 * SPM then resumes the original SP that was initially pre-empted.
 */
static struct ffa_value plat_ffa_preempted_vcpu_resume(
	struct vcpu_locked current_locked, struct vcpu **next)
{
	struct ffa_value ffa_ret = (struct ffa_value){.func = FFA_MSG_WAIT_32};
	struct vcpu *target_vcpu;
	struct vcpu *current = current_locked.vcpu;
	struct vcpu_locked target_locked;
	struct two_vcpu_locked vcpus_locked;

	CHECK(current->preempted_vcpu != NULL);
	CHECK(current->preempted_vcpu->state == VCPU_STATE_PREEMPTED);

	target_vcpu = current->preempted_vcpu;
	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, target_vcpu);
	current_locked = vcpus_locked.vcpu1;
	target_locked = vcpus_locked.vcpu2;

	/* Reset the fields tracking secure interrupt processing. */
	vcpu_secure_interrupt_complete(current_locked);

	/* SPMC scheduled call chain is completely unwound. */
	plat_ffa_exit_spmc_schedule_mode(current_locked);
	assert(current->call_chain.prev_node == NULL);

	current->state = VCPU_STATE_WAITING;

	vcpu_set_running(target_locked, NULL);

	vcpu_unlock(&target_locked);

	/* Restore interrupt priority mask. */
	plat_ffa_vcpu_allow_interrupts(current);

	/* The pre-empted vCPU should be run. */
	*next = target_vcpu;

	return ffa_ret;
}

static struct ffa_value ffa_msg_wait_complete(struct vcpu_locked current_locked,
					      struct vcpu **next)
{
	struct vcpu *current = current_locked.vcpu;

	current->scheduling_mode = NONE;
	current->rt_model = RTM_NONE;

	/* Relinquish control back to the NWd. */
	*next = api_switch_to_other_world(
		current_locked, (struct ffa_value){.func = FFA_MSG_WAIT_32},
		VCPU_STATE_WAITING);

	return api_ffa_interrupt_return(0);
}

/**
 * Deals with the common case of intercepting an FFA_MSG_WAIT call.
 */
static bool plat_ffa_msg_wait_intercept(struct vcpu_locked current_locked,
					struct vcpu **next,
					struct ffa_value *ffa_ret)
{
	struct two_vcpu_locked both_vcpu_locks;
	struct vcpu *current = current_locked.vcpu;
	bool ret = false;

	assert(next != NULL);
	assert(*next != NULL);

	vcpu_unlock(&current_locked);

	both_vcpu_locks = vcpu_lock_both(current, *next);

	/*
	 * Check if there are any pending secure virtual interrupts to
	 * be handled. The `next` should have a pointer to the current
	 * vCPU. Intercept call will set `ret` to FFA_INTERRUPT and the
	 * respective interrupt id.
	 */
	if (ffa_interrupts_intercept_call(both_vcpu_locks.vcpu1,
					  both_vcpu_locks.vcpu2, ffa_ret)) {
		*next = NULL;
		ret = true;
	}

	vcpu_unlock(&both_vcpu_locks.vcpu2);

	return ret;
}

/**
 * The invocation of FFA_MSG_WAIT at secure virtual FF-A instance is compliant
 * with FF-A v1.1 EAC0 specification. It only performs the state transition
 * from RUNNING to WAITING for the following Partition runtime models:
 * RTM_FFA_RUN, RTM_SEC_INTERRUPT, RTM_SP_INIT.
 */
struct ffa_value ffa_cpu_cycles_msg_wait_prepare(
	struct vcpu_locked current_locked, struct vcpu **next)
{
	struct ffa_value ret = api_ffa_interrupt_return(0);
	struct vcpu *current = current_locked.vcpu;

	switch (current->rt_model) {
	case RTM_SP_INIT:
		if (!sp_boot_next(current_locked, next)) {
			ret = ffa_msg_wait_complete(current_locked, next);

			if (plat_ffa_msg_wait_intercept(current_locked, next,
							&ret)) {
			}
		}
		break;
	case RTM_SEC_INTERRUPT:
		/*
		 * Either resume the preempted SP or complete the FFA_MSG_WAIT.
		 */
		assert(current->preempted_vcpu != NULL);
		plat_ffa_preempted_vcpu_resume(current_locked, next);

		if (plat_ffa_msg_wait_intercept(current_locked, next, &ret)) {
			break;
		}

		/*
		 * If CPU cycles were allocated through FFA_RUN interface,
		 * allow the interrupts(if they were masked earlier) before
		 * returning control to NWd.
		 */
		plat_ffa_vcpu_allow_interrupts(current);
		break;
	case RTM_FFA_RUN:
		ret = ffa_msg_wait_complete(current_locked, next);

		if (plat_ffa_msg_wait_intercept(current_locked, next, &ret)) {
			break;
		}

		/*
		 * If CPU cycles were allocated through FFA_RUN interface,
		 * allow the interrupts(if they were masked earlier) before
		 * returning control to NWd.
		 */
		plat_ffa_vcpu_allow_interrupts(current);

		break;
	default:
		panic("%s: unexpected runtime model %x for [%x %x]",
		      current->rt_model, current->vm->id,
		      cpu_index(current->cpu));
	}

	vcpu_unlock(&current_locked);

	return ret;
}

/**
 * Enforce action of an SP in response to non-secure or other-secure interrupt
 * by changing the priority mask. Effectively, physical interrupts shall not
 * trigger which has the same effect as queueing interrupts.
 */
static void plat_ffa_vcpu_queue_interrupts(
	struct vcpu_locked receiver_vcpu_locked)
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

/*
 * Initialize the scheduling mode and/or Partition Runtime model of the target
 * SP upon being resumed by an FFA_RUN ABI.
 */
void ffa_cpu_cycles_init_schedule_mode_ffa_runeld_prepare(
	struct vcpu_locked current_locked, struct vcpu_locked target_locked)
{
	struct vcpu *vcpu = target_locked.vcpu;
	struct vcpu *current = current_locked.vcpu;

	/*
	 * Scenario 1 in Table 8.4; Therefore SPMC could be resuming a vCPU
	 * that was part of NWd scheduled mode.
	 */
	CHECK(vcpu->scheduling_mode != SPMC_MODE);

	/* Section 8.2.3 bullet 4.2 of spec FF-A v1.1 EAC0. */
	if (vcpu->state == VCPU_STATE_WAITING) {
		assert(vcpu->rt_model == RTM_SP_INIT ||
		       vcpu->rt_model == RTM_NONE);
		vcpu->rt_model = RTM_FFA_RUN;

		if (!vm_id_is_current_world(current->vm->id) ||
		    (current->scheduling_mode == NWD_MODE)) {
			vcpu->scheduling_mode = NWD_MODE;
		}
	} else {
		/* SP vCPU would have been pre-empted earlier or blocked. */
		CHECK(vcpu->state == VCPU_STATE_PREEMPTED ||
		      vcpu->state == VCPU_STATE_BLOCKED);
	}

	plat_ffa_vcpu_queue_interrupts(target_locked);
}

/*
 * Prepare to yield execution back to the VM/SP that allocated CPU cycles and
 * move to BLOCKED state. If the CPU cycles were allocated to the current
 * execution context by the SPMC to handle secure virtual interrupt, then
 * FFA_YIELD invocation is essentially a no-op.
 */
struct ffa_value ffa_cpu_cycles_yield_prepare(struct vcpu_locked current_locked,
					      struct vcpu **next,
					      uint32_t timeout_low,
					      uint32_t timeout_high)
{
	struct ffa_value ret_args = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vcpu *current = current_locked.vcpu;
	struct ffa_value ret = {
		.func = FFA_YIELD_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
		.arg2 = timeout_low,
		.arg3 = timeout_high,
	};

	switch (current->rt_model) {
	case RTM_FFA_DIR_REQ:
		assert(current->direct_request_origin.vm_id !=
		       HF_INVALID_VM_ID);
		if (current->call_chain.prev_node == NULL) {
			/*
			 * Relinquish cycles to the NWd VM that sent direct
			 * request message to the current SP.
			 */
			*next = api_switch_to_other_world(current_locked, ret,
							  VCPU_STATE_BLOCKED);
		} else {
			/*
			 * Relinquish cycles to the SP that sent direct request
			 * message to the current SP.
			 */
			*next = api_switch_to_vm(
				current_locked, ret, VCPU_STATE_BLOCKED,
				current->direct_request_origin.vm_id);
		}
		break;
	case RTM_SEC_INTERRUPT: {
		/*
		 * SPMC does not implement a scheduler needed to resume the
		 * current vCPU upon timeout expiration. Hence, SPMC makes the
		 * implementation defined choice to treat FFA_YIELD invocation
		 * as a no-op if the SP execution context is in the secure
		 * interrupt runtime model. This does not violate FF-A spec as
		 * the spec does not mandate timeout to be honored. Moreover,
		 * timeout specified by an endpoint is just a hint to the
		 * partition manager which allocated CPU cycles.
		 * Resume the current vCPU.
		 */
		*next = NULL;
		break;
	}
	default:
		CHECK(current->rt_model == RTM_FFA_RUN);
		*next = api_switch_to_primary(current_locked, ret,
					      VCPU_STATE_BLOCKED);
		break;
	}

	/*
	 * Before yielding CPU cycles, allow the interrupts(if they were
	 * masked earlier).
	 */
	if (*next != NULL) {
		plat_ffa_vcpu_allow_interrupts(current);
	}

	return ret_args;
}
