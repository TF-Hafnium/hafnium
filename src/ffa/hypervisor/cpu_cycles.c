/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/other_world.h"

#include "hf/api.h"
#include "hf/ffa/indirect_messaging.h"
#include "hf/ffa_internal.h"
#include "hf/vcpu.h"

bool ffa_cpu_cycles_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
				struct ffa_value *ret)
{
	/*
	 * VM's requests should be forwarded to the SPMC, if target is an SP.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		*ret = arch_other_world_call_ext((struct ffa_value){
			.func = FFA_RUN_32, ffa_vm_vcpu(vm_id, vcpu_idx)});
		return true;
	}

	return false;
}

/**
 * Check if current VM can resume target VM/SP using FFA_RUN ABI.
 */
bool ffa_cpu_cycles_run_checks(struct vcpu_locked current_locked,
			       ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			       struct ffa_value *run_ret, struct vcpu **next)
{
	(void)next;
	(void)vcpu_idx;

	/* Only the primary VM can switch vCPUs. */
	if (!vm_is_primary(current_locked.vcpu->vm)) {
		run_ret->arg2 = FFA_DENIED;
		return false;
	}

	/* Only secondary VM vCPUs can be run. */
	if (target_vm_id == HF_PRIMARY_VM_ID) {
		return false;
	}

	return true;
}

/**
 * The invocation of FFA_MSG_WAIT at non-secure virtual FF-A instance is made
 * to be compliant with version v1.0 of the FF-A specification. It serves as
 * a blocking call.
 */
struct ffa_value ffa_cpu_cycles_msg_wait_prepare(
	struct vcpu_locked current_locked, struct vcpu **next)
{
	return ffa_indirect_msg_recv(true, current_locked, next);
}

bool ffa_cpu_cycles_check_runtime_state_transition(
	struct vcpu_locked current_locked, ffa_id_t vm_id,
	ffa_id_t receiver_vm_id, struct vcpu_locked receiver_locked,
	uint32_t func, enum vcpu_state *next_state)
{
	(void)current_locked;
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_locked;

	switch (func) {
	case FFA_YIELD_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
	case FFA_RUN_32:
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		*next_state = VCPU_STATE_WAITING;
		return true;
	default:
		return false;
	}
}

void ffa_cpu_cycles_init_schedule_mode_ffa_runeld_prepare(
	struct vcpu_locked current_locked, struct vcpu_locked target_locked)
{
	/* Scheduling mode not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)target_locked;
}

/*
 * Prepare to yield execution back to the VM that allocated cpu cycles and move
 * to BLOCKED state.
 */
struct ffa_value ffa_cpu_cycles_yield_prepare(struct vcpu_locked current_locked,
					      struct vcpu **next,
					      uint32_t timeout_low,
					      uint32_t timeout_high)
{
	struct vcpu *current = current_locked.vcpu;
	struct ffa_value ret = {
		.func = FFA_YIELD_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
		.arg2 = timeout_low,
		.arg3 = timeout_high,
	};

	/*
	 * Return execution to primary VM.
	 */
	*next = api_switch_to_primary(current_locked, ret, VCPU_STATE_BLOCKED);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value ffa_cpu_cycles_error_32(struct vcpu *current,
					 struct vcpu **next,
					 enum ffa_error error_code)
{
	(void)current;
	(void)next;
	(void)error_code;
	/* TODO: Interface not handled in hypervisor. */
	return ffa_error(FFA_NOT_SUPPORTED);
}
