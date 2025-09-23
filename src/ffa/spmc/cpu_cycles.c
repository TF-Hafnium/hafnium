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
#include "hf/ffa/direct_messaging.h"
#include "hf/ffa/interrupts.h"
#include "hf/ffa/vm.h"
#include "hf/ffa_internal.h"
#include "hf/load.h"
#include "hf/plat/interrupts.h"
#include "hf/vm.h"

#include "smc.h"

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
			if (vcpu_virt_interrupt_count_get(current_locked) > 0) {
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
	}

out:
	vcpu_unlock(&target_locked);
	return ret;
}

/**
 * SPMC scheduled call chain is completely unwound.
 */
static void ffa_cpu_cycles_exit_spmc_schedule_mode(
	struct vcpu_locked current_locked)
{
	struct vcpu *current;

	current = current_locked.vcpu;
	assert(current->call_chain.next_node == NULL);
	CHECK(current->scheduling_mode == SPMC_MODE);

	vcpu_reset_mode(current_locked);
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
static struct ffa_value ffa_cpu_cycles_preempted_vcpu_resume(
	struct vcpu_locked current_locked, struct vcpu **next,
	enum vcpu_state to_state)
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
	ffa_cpu_cycles_exit_spmc_schedule_mode(current_locked);
	assert(current->call_chain.prev_node == NULL);

	CHECK(vcpu_state_set(current_locked, to_state));

	vcpu_set_running(target_locked, NULL);

	vcpu_unlock(&target_locked);

	/* Restore interrupt priority mask. */
	ffa_interrupts_unmask(current);

	/* The pre-empted vCPU should be run. */
	*next = target_vcpu;

	return ffa_ret;
}

static void ffa_msg_wait_complete(struct vcpu_locked current_locked,
				  struct vcpu **next)
{
	vcpu_reset_mode(current_locked);

	/*
	 * We no longer need to do a managed exit so clear the interrupt if
	 * needed.
	 */
	vcpu_virt_interrupt_clear(current_locked, HF_MANAGED_EXIT_INTID);

	/* Relinquish control back to the NWd. */
	*next = api_switch_to_other_world(
		current_locked, (struct ffa_value){.func = FFA_MSG_WAIT_32},
		VCPU_STATE_WAITING);
}

/**
 * Deals with the common case of intercepting an FFA_MSG_WAIT call.
 */
static bool ffa_cpu_cycles_msg_wait_intercept(struct vcpu_locked current_locked,
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
	 * Check if there is a pending interrupt, and if the partition
	 * is expects to notify the scheduler or resume straight away.
	 * Either trigger SRI for later donation of CPU cycles, or
	 * eret `FFA_INTERRUPT` back to the caller.
	 */
	if (ffa_interrupts_intercept_call(both_vcpu_locks.vcpu1,
					  both_vcpu_locks.vcpu2, ffa_ret)) {
		*next = NULL;
		ret = true;
	}

	vcpu_unlock(&both_vcpu_locks.vcpu2);

	return ret;
}

static bool sp_boot_next(struct vcpu_locked current_locked, struct vcpu **next,
			 enum vcpu_state to_state)
{
	struct vcpu *vcpu_next = NULL;
	struct vcpu *current = current_locked.vcpu;
	struct vm *next_vm;
	size_t cpu_indx = cpu_index(current->cpu);

	if (current->cpu->last_sp_initialized) {
		return false;
	}

	if (vm_read_state(current->vm) != VM_STATE_ABORTING) {
		/* vCPU has just returned from successful initialization. */
		dlog_verbose(
			"Initialized execution context of VM: %#x on CPU: %zu, "
			"boot_order: %u\n",
			current->vm->id, cpu_index(current->cpu),
			current->vm->boot_order);
	}

	if (cpu_indx == PRIMARY_CPU_IDX) {
		next_vm = vm_get_next_boot(current->vm);
	} else {
		/* SP boot chain on secondary CPU. */
		next_vm = vm_get_next_boot_secondary_core(current->vm);
	}

	CHECK(vcpu_state_set(current_locked, to_state));
	vcpu_reset_mode(current_locked);

	/*
	 * Pick next SP's vCPU to be booted. Once all SPs have booted
	 * (next_vm is NULL), then return execution to NWd.
	 */
	if (next_vm == NULL) {
		current->cpu->last_sp_initialized = true;
		goto out;
	}

	vcpu_next = vm_get_vcpu(next_vm, cpu_indx);

	/*
	 * An SP's execution context needs to be bootstrapped if:
	 * - It has never been initialized before.
	 * - Or it was turned off when the CPU, on which it was pinned, was
	 *   powered down.
	 */
	if (vcpu_next->rt_model == RTM_SP_INIT ||
	    vcpu_next->state == VCPU_STATE_OFF) {
		struct vcpu_locked vcpu_next_locked;
		struct vm_locked vm_locked;

		vm_locked = vm_lock(next_vm);
		vcpu_next_locked = vcpu_lock(vcpu_next);

		if (cpu_indx == PRIMARY_CPU_IDX &&
		    vcpu_next->state == VCPU_STATE_CREATED) {
			vm_set_state(vm_locked, VM_STATE_RUNNING);
		}

		vm_unlock(&vm_locked);

		vcpu_bootstrap(vcpu_next_locked, current->cpu, true);

		vcpu_unlock(&vcpu_next_locked);
		*next = vcpu_next;

		return true;
	}
out:
	dlog_notice("Finished bootstrapping all SPs on CPU%lx\n", cpu_indx);
	return false;
}

/**
 * SPMC could have restarted the current vCPU if it had aborted earlier due to
 * a fatal error. This current vCPU could have been a part of a call chain.
 * SPMC resumes the halted vcpu now.
 */
static void resume_halted_vcpu_upon_restart(struct vcpu_locked current_locked,
					    struct vcpu **next)
{
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *target_vcpu;
	struct vcpu_locked target_locked;
	struct two_vcpu_locked vcpus_locked;

	CHECK(current->halted_vcpu != NULL);

	target_vcpu = current->halted_vcpu;
	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, target_vcpu);
	current_locked = vcpus_locked.vcpu1;
	target_locked = vcpus_locked.vcpu2;

	/* Reset the relevant fields for current vCPU. */
	current->halted_vcpu = NULL;
	vcpu_reset_mode(current_locked);

	/* The current vCPU now moves to WAITING state. */
	CHECK(vcpu_state_set(current_locked, VCPU_STATE_WAITING));

	vcpu_set_running(target_locked, NULL);
	vcpu_unlock(&target_locked);

	/* The pre-empted vCPU should be run. */
	*next = target_vcpu;
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
		if (current_locked.vcpu->halted_vcpu != NULL) {
			resume_halted_vcpu_upon_restart(current_locked, next);
			dlog_info("Successfully restarted vCPU of SP: %#x\n",
				  current->vm->id);
		} else if (!sp_boot_next(current_locked, next,
					 VCPU_STATE_WAITING)) {
			ffa_msg_wait_complete(current_locked, next);

			ffa_cpu_cycles_msg_wait_intercept(current_locked, next,
							  &ret);
		}
		break;
	case RTM_SEC_INTERRUPT:
		/*
		 * Either resume the preempted SP or complete the FFA_MSG_WAIT.
		 */
		assert(current->preempted_vcpu != NULL);
		ffa_cpu_cycles_preempted_vcpu_resume(current_locked, next,
						     VCPU_STATE_WAITING);

		if (!ffa_cpu_cycles_msg_wait_intercept(current_locked, next,
						       &ret)) {
			/*
			 * If CPU cycles were allocated through FFA_RUN
			 * interface, allow the interrupts(if they were masked
			 * earlier) before returning control to NWd.
			 */
			ffa_interrupts_unmask(current);
		}

		break;
	case RTM_FFA_RUN:
		ffa_msg_wait_complete(current_locked, next);

		if (!ffa_cpu_cycles_msg_wait_intercept(current_locked, next,
						       &ret)) {
			/*
			 * If CPU cycles were allocated through FFA_RUN
			 * interface, allow the interrupts(if they were masked
			 * earlier) before returning control to NWd.
			 */
			ffa_interrupts_unmask(current);
		}

		break;
	default:
		panic("%s: unexpected runtime model %x for [%x %x]",
		      current->rt_model, current->vm->id,
		      cpu_index(current->cpu));
	}

	vcpu_unlock(&current_locked);

	return ret;
}

/*
 * Initialize the scheduling mode and/or Partition Runtime model of the target
 * SP upon being resumed by an FFA_RUN ABI.
 */
void ffa_cpu_cycles_init_schedule_mode_ffa_run(
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

	ffa_interrupts_mask(target_locked);
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
			struct two_vcpu_locked vcpus_locked;

			/*
			 * Relinquish cycles to the SP that sent direct request
			 * message to the current SP.
			 */
			*next = api_switch_to_vm(
				current_locked, ret, VCPU_STATE_BLOCKED,
				current->direct_request_origin.vm_id);

			vcpu_unlock(&current_locked);

			/* Lock both vCPUs at once to avoid deadlock. */
			vcpus_locked = vcpu_lock_both(current, *next);

			vcpu_state_set(vcpus_locked.vcpu2, VCPU_STATE_RUNNING);
			vcpu_unlock(&vcpus_locked.vcpu2);
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
		ffa_interrupts_unmask(current);
	}

	return ret_args;
}

/**
 * Validates the Runtime model for FFA_RUN. Refer to section 7.2 of the FF-A
 * v1.1 EAC0 spec.
 */
static bool ffa_cpu_cycles_check_rtm_ffa_run(struct vcpu_locked current_locked,
					     struct vcpu_locked locked_vcpu,
					     uint32_t func,
					     enum vcpu_state *next_state)
{
	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		[[fallthrough]];
	case FFA_RUN_32: {
		/* Rules 1,2 section 7.2 EAC0 spec. */
		if (ffa_direct_msg_precedes_in_call_chain(current_locked,
							  locked_vcpu)) {
			return false;
		}
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	}
	case FFA_MSG_WAIT_32:
		/* Rule 4 section 7.2 EAC0 spec. Fall through. */
		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_YIELD_32:
		/* Rule 5 section 7.2 EAC0 spec. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_ABORT_32:
	case FFA_ABORT_64:
		/* Rule I0072 in section 7.2.4 of FF-A v1.3 ALP2 spec. */
		*next_state = VCPU_STATE_ABORTED;
		return true;
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 3 section 7.2 EAC0 spec. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Validates the Runtime model for FFA_MSG_SEND_DIRECT_REQ and
 * FFA_MSG_SEND_DIRECT_REQ2. Refer to section 8.3 of the FF-A
 * v1.2 spec.
 */
static bool ffa_cpu_cycles_check_rtm_ffa_dir_req(
	struct vcpu_locked current_locked, struct vcpu_locked locked_vcpu,
	ffa_id_t receiver_vm_id, uint32_t func, enum vcpu_state *next_state)
{
	/*
	 * SPMC denies invocation if the SP's vCPU is processing a PSCI power
	 * management operation.
	 */
	if (current_locked.vcpu->pwr_mgmt_op != PWR_MGMT_NONE) {
		switch (func) {
		case FFA_MSG_SEND_DIRECT_REQ_64:
		case FFA_MSG_SEND_DIRECT_REQ_32:
		case FFA_MSG_SEND_DIRECT_REQ2_64:
		case FFA_RUN_32:
		case FFA_YIELD_32:
			dlog_verbose(
				"State transition denied during power "
				"management operation\n");
			return false;
		default:
			break;
		}
	}

	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		[[fallthrough]];
	case FFA_RUN_32: {
		/* Rules 1,2. */
		if (ffa_direct_msg_precedes_in_call_chain(current_locked,
							  locked_vcpu)) {
			return false;
		}

		*next_state = VCPU_STATE_BLOCKED;
		return true;
	}
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64: {
		/* Rule 3. */
		if (current_locked.vcpu->direct_request_origin.vm_id ==
		    receiver_vm_id) {
			*next_state = VCPU_STATE_WAITING;
			return true;
		}

		return false;
	}
	case FFA_YIELD_32:
		/* Rule 3, section 8.3 of FF-A v1.2 spec. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_ABORT_32:
	case FFA_ABORT_64:
		/* Rule I0072 in section 7.2.4 of FF-A v1.3 ALP2 spec. */
		*next_state = VCPU_STATE_ABORTED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Rule 4. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Validates the Runtime model for Secure interrupt handling. Refer to section
 * 8.4 of the FF-A v1.2 ALP0 spec.
 */
static bool ffa_cpu_cycles_check_rtm_sec_interrupt(
	struct vcpu_locked current_locked, struct vcpu_locked locked_vcpu,
	uint32_t func, enum vcpu_state *next_state)
{
	struct vcpu *current = current_locked.vcpu;
	struct vcpu *vcpu = locked_vcpu.vcpu;

	CHECK(current->scheduling_mode == SPMC_MODE);

	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		/* Rule 3. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_RUN_32: {
		/* Rule 6. */
		if (vcpu->state == VCPU_STATE_PREEMPTED) {
			*next_state = VCPU_STATE_BLOCKED;
			return true;
		}

		return false;
	}
	case FFA_MSG_WAIT_32:
		/* Rule 2. */
		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_YIELD_32:
		/* Rule 3, section 8.4 of FF-A v1.2 spec. */
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_ABORT_32:
	case FFA_ABORT_64:
		/* Rule I0072 in section 7.2.4 of FF-A v1.3 ALP2 spec. */
		*next_state = VCPU_STATE_ABORTED;
		return true;
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 5. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Validates the Runtime model for SP initialization. Refer to section
 * 8.3 of the FF-A v1.2 ALP0 spec.
 */
static bool ffa_cpu_cycles_check_rtm_sp_init(struct vcpu_locked current_locked,
					     struct vcpu_locked locked_vcpu,
					     uint32_t func,
					     enum vcpu_state *next_state)
{
	switch (func) {
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64: {
		struct vcpu *vcpu = locked_vcpu.vcpu;

		assert(vcpu != NULL);
		/* Rule 1. */
		if (vcpu->rt_model != RTM_SP_INIT) {
			*next_state = VCPU_STATE_BLOCKED;
			return true;
		}

		return false;
	}
	case FFA_MSG_WAIT_32:
		/* Rule 2. */
		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_ERROR_32:
		/* Refer rule I0096 in FF-A v1.3 ALP2 spec.  */
		if (current_locked.vcpu->vm->ffa_version > FFA_VERSION_1_2) {
			return false;
		}

		*next_state = VCPU_STATE_WAITING;
		return true;
	case FFA_ABORT_32:
	case FFA_ABORT_64:
		/* Rule I0072 in section 7.2.4 of FF-A v1.3 ALP2 spec. */
		*next_state = VCPU_STATE_ABORTED;
		return true;
	case FFA_YIELD_32:
		/* Rule 4. Fall through. */
	case FFA_RUN_32:
		/* Rule 6. Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		/* Rule 5. Fall through. */
	default:
		/* Deny state transitions by default. */
		return false;
	}
}

/**
 * Check if the runtime model (state machine) of the current SP supports the
 * given FF-A ABI invocation. If yes, next_state represents the state to which
 * the current vcpu would transition upon the FF-A ABI invocation as determined
 * by the Partition runtime model.
 */
bool ffa_cpu_cycles_check_runtime_state_transition(
	struct vcpu_locked current_locked, ffa_id_t vm_id,
	ffa_id_t receiver_vm_id, struct vcpu_locked locked_vcpu, uint32_t func,
	enum vcpu_state *next_state)
{
	bool allowed = false;
	struct vcpu *current = current_locked.vcpu;

	assert(current != NULL);

	/* Perform state transition checks only for Secure Partitions. */
	if (!vm_id_is_current_world(vm_id)) {
		return true;
	}

	switch (current->rt_model) {
	case RTM_FFA_RUN:
		allowed = ffa_cpu_cycles_check_rtm_ffa_run(
			current_locked, locked_vcpu, func, next_state);
		break;
	case RTM_FFA_DIR_REQ:
		allowed = ffa_cpu_cycles_check_rtm_ffa_dir_req(
			current_locked, locked_vcpu, receiver_vm_id, func,
			next_state);
		break;
	case RTM_SEC_INTERRUPT:
		allowed = ffa_cpu_cycles_check_rtm_sec_interrupt(
			current_locked, locked_vcpu, func, next_state);
		break;
	case RTM_SP_INIT:
		allowed = ffa_cpu_cycles_check_rtm_sp_init(
			current_locked, locked_vcpu, func, next_state);
		break;
	default:
		dlog_error(
			"Illegal Runtime Model specified by SP%x on CPU%zx\n",
			current->vm->id, cpu_index(current->cpu));
		allowed = false;
		break;
	}

	if (!allowed) {
		dlog_verbose("State transition denied\n");
	}

	return allowed;
}

/*
 * Handle FFA_ERROR_32 call according to the given error code.
 *
 * Error codes other than FFA_ABORTED, and cases of FFA_ABORTED not
 * in RTM_SP_INIT runtime model, not implemented. Refer to section 8.5
 * of FF-A 1.2 spec.
 */
struct ffa_value ffa_cpu_cycles_error_32(struct vcpu *current,
					 struct vcpu **next,
					 enum ffa_error error_code,
					 struct mpool *ppool)
{
	struct vcpu_locked current_locked;
	struct vm_locked vm_locked;
	enum partition_runtime_model rt_model;
	struct ffa_value ret = api_ffa_interrupt_return(0);

	vm_locked = vm_lock(current->vm);
	current_locked = vcpu_lock(current);
	rt_model = current_locked.vcpu->rt_model;

	if (error_code == FFA_ABORTED && rt_model == RTM_SP_INIT) {
		dlog_error("Aborting SP %#x from vCPU %u\n", current->vm->id,
			   vcpu_index(current));

		CHECK(vm_set_state(vm_locked, VM_STATE_ABORTING));
		ffa_vm_free_resources(vm_locked, ppool);

		if (sp_boot_next(current_locked, next, VCPU_STATE_WAITING)) {
			goto out;
		}

		/*
		 * Relinquish control back to the NWd. Return
		 * FFA_MSG_WAIT_32 to indicate to SPMD that SPMC
		 * has successfully finished initialization.
		 */
		*next = api_switch_to_other_world(
			current_locked,
			(struct ffa_value){.func = FFA_MSG_WAIT_32},
			VCPU_STATE_ABORTED);

		goto out;
	}
	ret = ffa_error(FFA_NOT_SUPPORTED);
out:
	vcpu_unlock(&current_locked);
	vm_unlock(&vm_locked);
	return ret;
}

/*
 * Perform appropriate operations based on the abort action specified by
 * partition.
 */
static struct ffa_value abort_action_process(struct vcpu_locked current_locked,
					     struct vcpu **next,
					     enum vcpu_state to_state)
{
	struct ffa_value ret_args = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vcpu *current = current_locked.vcpu;
	struct ffa_value to_ret = ffa_error(FFA_ABORTED);

	assert(to_state == VCPU_STATE_NULL || to_state == VCPU_STATE_STOPPED ||
	       to_state == VCPU_STATE_ABORTED);

	switch (current->rt_model) {
	case RTM_FFA_DIR_REQ:
		/*
		 * Three possible scenarios here:
		 * Scenario A: A normal world VM sent a direct request message
		 * to SPx.
		 * Scenario B: A secure world SP extended a normal world call
		 * chain by sending a direct request message to SPx.
		 * Scenario C: A secure interrupt, whose target is SPy,
		 * preempted a VM/SP. SPy, while handling the secure virtual
		 * interrupt, sent a direct request to SPx.
		 *
		 * Eventually, the vCPU of SPx (i.e. current) aborted while
		 * handling the direct request message.
		 */
		struct vcpu_locked next_locked = (struct vcpu_locked){
			.vcpu = NULL,
		};
		assert(current->direct_request_origin.vm_id !=
		       HF_INVALID_VM_ID);

		api_direct_resp_unwind_call_chain_resume_target(
			&current_locked, next, &next_locked, to_ret, to_state);

		vcpu_unlock(&next_locked);
		break;
	case RTM_SEC_INTERRUPT:
		/*
		 * Two possible scenarios here:
		 * Scenario A: A secure interrupt, whose target is SPx,
		 * preempted a normal world VM.
		 * Scenario B: A secure interrupt, whose target is SPx,
		 * preempted a secure world SP.
		 *
		 * Eventually, the vCPU of SPx (i.e., current) aborted while
		 * handling the secure virtual interrupt.
		 */
		assert(current->call_chain.prev_node == NULL);
		assert(current->preempted_vcpu != NULL);

		ffa_cpu_cycles_preempted_vcpu_resume(current_locked, next,
						     to_state);
		break;
	case RTM_SP_INIT:
		if (!sp_boot_next(current_locked, next, to_state)) {
			/*
			 * Relinquish control back to the NWd. Return
			 * FFA_MSG_WAIT_32 to indicate to SPMD that SPMC
			 * has successfully finished initialization.
			 */
			*next = api_switch_to_other_world(
				current_locked,
				(struct ffa_value){.func = FFA_MSG_WAIT_32},
				to_state);
		}
		break;
	default:
		CHECK(current->rt_model == RTM_FFA_RUN);
		*next = api_switch_to_primary(current_locked, to_ret, to_state);
	}

	vcpu_reset_mode(current_locked);

	/*
	 * Before yielding CPU cycles, allow the interrupts(if they were
	 * masked earlier).
	 */
	if (*next != NULL) {
		ffa_interrupts_unmask(current);
	}

	return ret_args;
}

struct ffa_value ffa_cpu_cycles_abort(struct vcpu_locked *current_locked,
				      struct vcpu **next)
{
	enum abort_action abort_action;

	/*
	 * Disable the current vCPU's arch timer and remove its corresponding
	 * entry from timer list of current CPU.
	 * The current vCPU does not have IPI list entry since it belongs to a
	 * UP SP.
	 */
	current_locked->vcpu->regs.arch_timer.ctl = 0U;
	timer_vcpu_manage(current_locked->vcpu);

	abort_action = current_locked->vcpu->vm->abort_action;

	switch (abort_action) {
	case ACTION_PROPAGATE:
		dlog_error(
			"Propagating fatal error to SPMD through FFA_ABORT\n");

		smc_ffa_call((struct ffa_value){.func = FFA_ABORT_32});

		/*
		 * The above FFA_ABORT invocation to SPMD is not expected to
		 * return.
		 */
		panic("Not expected to return from FFA_ABORT to SPMD\n");

		/* Not reachable. Return dummy status. */
		return (struct ffa_value){.func = FFA_ERROR_32};
	case ACTION_STOP:
		return abort_action_process(*current_locked, next,
					    VCPU_STATE_STOPPED);
	case ACTION_DESTROY:
		return abort_action_process(*current_locked, next,
					    VCPU_STATE_NULL);
	case ACTION_IMP_DEF:
		/*
		 * Implementation defined action allowed by spec.
		 * Legacy partition: Destroy it or keep in aborted state?
		 * Partition with lifecycle support: STOP it.
		 */
		if (current_locked->vcpu->vm->lifecycle_support) {
			return abort_action_process(*current_locked, next,
						    VCPU_STATE_STOPPED);
		}
		return abort_action_process(*current_locked, next,
					    VCPU_STATE_ABORTED);
	case ACTION_RESTART: {
		struct vcpu *halted_vcpu;
		struct ffa_value ret;
		struct vcpu *current = current_locked->vcpu;
		struct cpu *cpu = current->cpu;
		struct vm *vm = current->vm;
		struct vm_locked vm_locked;

		ret = abort_action_process(*current_locked, &halted_vcpu,
					   VCPU_STATE_STOPPED);

		/* This vCPU is going to be sanitized.*/
		vcpu_unlock(current_locked);

		/*
		 * Re-initialize the current vCPU's partition i.e., move it from
		 * STOPPED state to CREATED state by re-allocating resources.
		 */
		CHECK(load_reinit_partition(vm, api_get_ppool()));

		vm_locked = vm_lock(vm);
		assert(vm_read_state(vm) == VM_STATE_CREATED);
		vm_set_state(vm_locked, VM_STATE_RUNNING);
		vm_unlock(&vm_locked);

		/*
		 * Obtain the current vCPU as it has been purged earlier during
		 * partition reinitialization.
		 */
		current = vm_get_vcpu(vm, cpu_index(cpu));

		/* Bootstrap the restarted vCPU as on cold boot. */
		*current_locked = vcpu_lock(current);
		vcpu_bootstrap(*current_locked, cpu,
			       (cpu_index(cpu) == PRIMARY_CPU_IDX));

		/*
		 * SPMC restarts the current vCPU (i.e., STARTING state) and
		 * records the halted vcpu to be resumed once the current vCPU
		 * re-initializes itself.
		 */
		*next = current;

		/*
		 * Keep a record of halted vCPU which will be resumed by SPMC
		 * once current vCPU successfully reinitializes.
		 */
		current->halted_vcpu = halted_vcpu;
		dlog_info("Ready to restart vcpu of SP:%#x\n",
			  current_locked->vcpu->vm->id);

		return ret;
	}
	default:
		panic("Unsupported abort action\n");
	}
}
