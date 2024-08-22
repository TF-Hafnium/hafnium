/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "psci_handler.h"

#include <stdint.h>

#include "hf/arch/plat/psci.h"
#include "hf/arch/types.h"

#include "hf/api.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/panic.h"
#include "hf/vm.h"

#include "psci.h"

void cpu_entry(struct cpu *c);

/**
 * Handles PSCI requests received via HVC or SMC instructions from the primary
 * VM.
 *
 * A minimal PSCI 1.1 interface is offered which can make use of the
 * implementation of PSCI in EL3 by acting as an adapter.
 *
 * Returns true if the request was a PSCI one, false otherwise.
 */
bool psci_primary_vm_handler(struct vcpu *vcpu, uint32_t func, uintreg_t arg0,
			     uintreg_t arg1, uintreg_t arg2, uintreg_t *ret)
{
	struct cpu *c;
	struct ffa_value smc_res;
	struct vcpu *vcpu_target;
	struct vcpu_locked vcpu_locked;

	/*
	 * If there's a problem with the EL3 PSCI, block standard secure service
	 * calls by marking them as unknown. Other calls will be allowed to pass
	 * through.
	 *
	 * This blocks more calls than just PSCI so it may need to be made more
	 * lenient in future.
	 */

	if (plat_psci_version_get() == 0) {
		*ret = SMCCC_ERROR_UNKNOWN;
		return (func & SMCCC_SERVICE_CALL_MASK) ==
		       SMCCC_STANDARD_SECURE_SERVICE_CALL;
	}

	switch (func & ~SMCCC_CONVENTION_MASK) {
	case PSCI_VERSION:
		*ret = PSCI_VERSION_1_1;
		break;

	case PSCI_FEATURES:
		switch (arg0 & ~SMCCC_CONVENTION_MASK) {
		case SMCCC_VERSION_FUNC_ID:
			*ret = SMCCC_VERSION_1_2;
			break;

		case PSCI_CPU_SUSPEND:
			if (plat_psci_version_get() == PSCI_VERSION_0_2) {
				/*
				 * PSCI 0.2 doesn't support PSCI_FEATURES so
				 * report PSCI 0.2 compatible features.
				 */
				*ret = 0;
			} else {
				/* PSCI 1.x only defines two feature bits. */
				smc_res = smc32(func, arg0, 0, 0, 0, 0, 0,
						SMCCC_CALLER_HYPERVISOR);
				*ret = smc_res.func & 0x3;
			}
			break;

		case PSCI_VERSION:
		case PSCI_FEATURES:
		case PSCI_SYSTEM_OFF:
		case PSCI_SYSTEM_RESET:
		case PSCI_AFFINITY_INFO:
		case PSCI_CPU_OFF:
		case PSCI_CPU_ON:
			/* These are supported without special features. */
			*ret = 0;
			break;

		default:
			/* Everything else is unsupported. */
			*ret = PSCI_ERROR_NOT_SUPPORTED;
			break;
		}
		break;

	case PSCI_SYSTEM_OFF:
		smc32(PSCI_SYSTEM_OFF, 0, 0, 0, 0, 0, 0,
		      SMCCC_CALLER_HYPERVISOR);
		panic("System off failed");
		break;

	case PSCI_SYSTEM_RESET:
		smc32(PSCI_SYSTEM_RESET, 0, 0, 0, 0, 0, 0,
		      SMCCC_CALLER_HYPERVISOR);
		panic("System reset failed");
		break;

	case PSCI_AFFINITY_INFO:
		c = cpu_find(arg0);
		if (!c) {
			*ret = PSCI_ERROR_INVALID_PARAMETERS;
			break;
		}

		if (arg1 != 0) {
			*ret = PSCI_ERROR_NOT_SUPPORTED;
			break;
		}

		sl_lock(&c->lock);
		if (c->is_on) {
			*ret = PSCI_RETURN_ON;
		} else {
			*ret = PSCI_RETURN_OFF;
		}
		sl_unlock(&c->lock);
		break;

	case PSCI_CPU_SUSPEND: {
		plat_psci_cpu_suspend(arg0);
		/*
		 * Update vCPU state to wake from the provided entry point but
		 * if suspend returns, for example because it failed or was a
		 * standby power state, the SMC will return and the updated
		 * vCPU registers will be ignored.
		 */
		arch_regs_set_pc_arg(&vcpu->regs, ipa_init(arg1), arg2);
		smc_res = smc64(PSCI_CPU_SUSPEND, arg0, (uintreg_t)&cpu_entry,
				(uintreg_t)vcpu->cpu, 0, 0, 0,
				SMCCC_CALLER_HYPERVISOR);
		*ret = smc_res.func;
		break;
	}

	case PSCI_CPU_OFF:
		cpu_off(vcpu->cpu);
		smc32(PSCI_CPU_OFF, 0, 0, 0, 0, 0, 0, SMCCC_CALLER_HYPERVISOR);
		panic("CPU off failed");
		break;

	case PSCI_CPU_ON:
		c = cpu_find(arg0);
		if (!c) {
			*ret = PSCI_ERROR_INVALID_PARAMETERS;
			break;
		}

		if (cpu_on(c)) {
			*ret = PSCI_ERROR_ALREADY_ON;
			break;
		}

		vcpu_target = vm_get_vcpu(vcpu->vm, cpu_index(c));
		vcpu_locked = vcpu_lock(vcpu_target);
		vcpu_on(vcpu_locked, ipa_init(arg1), arg2);
		vcpu_unlock(&vcpu_locked);

		/*
		 * There's a race when turning a CPU on when it's in the
		 * process of turning off. We need to loop here while it is
		 * reported that the CPU is on (because it's about to turn
		 * itself off).
		 */
		do {
			smc_res = smc64(PSCI_CPU_ON, arg0,
					(uintreg_t)&cpu_entry, (uintreg_t)c, 0,
					0, 0, SMCCC_CALLER_HYPERVISOR);
			*ret = smc_res.func;
		} while (*ret == (uintreg_t)PSCI_ERROR_ALREADY_ON);

		if (*ret != PSCI_RETURN_SUCCESS) {
			cpu_off(c);
		}
		break;

	case PSCI_MIGRATE:
	case PSCI_MIGRATE_INFO_TYPE:
	case PSCI_MIGRATE_INFO_UP_CPU:
	case PSCI_CPU_FREEZE:
	case PSCI_CPU_DEFAULT_SUSPEND:
	case PSCI_NODE_HW_STATE:
	case PSCI_SYSTEM_SUSPEND:
	case PSCI_SET_SYSPEND_MODE:
	case PSCI_STAT_RESIDENCY:
	case PSCI_STAT_COUNT:
	case PSCI_SYSTEM_RESET2:
	case PSCI_MEM_PROTECT:
	case PSCI_MEM_PROTECT_CHECK_RANGE:
		/* Block all other known PSCI calls. */
		*ret = PSCI_ERROR_NOT_SUPPORTED;
		break;

	default:
		return false;
	}

	return true;
}

/**
 * Handles PSCI requests received via HVC or SMC instructions from a secondary
 * VM.
 *
 * A minimal PSCI 1.1 interface is offered which can start and stop vCPUs in
 * collaboration with the scheduler in the primary VM.
 *
 * Returns true if the request was a PSCI one, false otherwise.
 */
bool psci_secondary_vm_handler(struct vcpu *vcpu, uint32_t func, uintreg_t arg0,
			       uintreg_t arg1, uintreg_t arg2, uintreg_t *ret,
			       struct vcpu **next)
{
	switch (func & ~SMCCC_CONVENTION_MASK) {
	case PSCI_VERSION:
		*ret = PSCI_VERSION_1_1;
		break;

	case PSCI_FEATURES:
		switch (arg0 & ~SMCCC_CONVENTION_MASK) {
		case PSCI_CPU_SUSPEND:
			/*
			 * Does not offer OS-initiated mode but does use
			 * extended StateID Format.
			 */
			*ret = 0x2;
			break;

		case PSCI_VERSION:
		case PSCI_FEATURES:
		case PSCI_AFFINITY_INFO:
		case PSCI_CPU_OFF:
		case PSCI_CPU_ON:
			/* These are supported without special features. */
			*ret = 0;
			break;

		default:
			/* Everything else is unsupported. */
			*ret = PSCI_ERROR_NOT_SUPPORTED;
			break;
		}
		break;

	case PSCI_AFFINITY_INFO: {
		cpu_id_t target_affinity = arg0;
		uint32_t lowest_affinity_level = arg1;
		struct vm *vm = vcpu->vm;
		struct vcpu_locked target_vcpu;
		ffa_vcpu_index_t target_vcpu_index =
			vcpu_id_to_index(target_affinity);

		if (lowest_affinity_level != 0) {
			/* Affinity levels greater than 0 not supported. */
			*ret = PSCI_ERROR_INVALID_PARAMETERS;
			break;
		}

		if (target_vcpu_index >= vm->vcpu_count) {
			*ret = PSCI_ERROR_INVALID_PARAMETERS;
			break;
		}

		target_vcpu = vcpu_lock(vm_get_vcpu(vm, target_vcpu_index));
		*ret = vcpu_is_off(target_vcpu) ? PSCI_RETURN_OFF
						: PSCI_RETURN_ON;
		vcpu_unlock(&target_vcpu);
		break;
	}

	case PSCI_CPU_SUSPEND: {
		/*
		 * Downgrade suspend request to WFI and return SUCCESS, as
		 * allowed by the specification.
		 */
		*next = api_wait_for_interrupt(vcpu);
		*ret = PSCI_RETURN_SUCCESS;
		break;
	}

	case PSCI_CPU_OFF:
		/*
		 * Should never return to the caller, but in case it somehow
		 * does.
		 */
		*ret = PSCI_ERROR_DENIED;
		/* Tell the scheduler not to run the vCPU again. */
		*next = api_vcpu_off(vcpu);
		break;

	case PSCI_CPU_ON: {
		/* Parameter names as per PSCI specification. */
		cpu_id_t target_cpu = arg0;
		ipaddr_t entry_point_address = ipa_init(arg1);
		uint64_t context_id = arg2;
		ffa_vcpu_index_t target_vcpu_index =
			vcpu_id_to_index(target_cpu);
		struct vm *vm = vcpu->vm;
		struct vcpu *target_vcpu;
		struct vcpu_locked vcpu_locked;
		bool vcpu_was_off;

		if (target_vcpu_index >= vm->vcpu_count) {
			*ret = PSCI_ERROR_INVALID_PARAMETERS;
			break;
		}

		target_vcpu = vm_get_vcpu(vm, target_vcpu_index);
		vcpu_locked = vcpu_lock(target_vcpu);
		vcpu_was_off = vcpu_secondary_reset_and_start(
			vcpu_locked, entry_point_address, context_id);
		vcpu_unlock(&vcpu_locked);

		if (vcpu_was_off) {
			/*
			 * Tell the scheduler that it can start running the new
			 * vCPU now.
			 */
			*next = api_wake_up(vcpu, target_vcpu);
			*ret = PSCI_RETURN_SUCCESS;
		} else {
			*ret = PSCI_ERROR_ALREADY_ON;
		}

		break;
	}

	case PSCI_SYSTEM_OFF:
	case PSCI_SYSTEM_RESET:
	case PSCI_MIGRATE:
	case PSCI_MIGRATE_INFO_TYPE:
	case PSCI_MIGRATE_INFO_UP_CPU:
	case PSCI_CPU_FREEZE:
	case PSCI_CPU_DEFAULT_SUSPEND:
	case PSCI_NODE_HW_STATE:
	case PSCI_SYSTEM_SUSPEND:
	case PSCI_SET_SYSPEND_MODE:
	case PSCI_STAT_RESIDENCY:
	case PSCI_STAT_COUNT:
	case PSCI_SYSTEM_RESET2:
	case PSCI_MEM_PROTECT:
	case PSCI_MEM_PROTECT_CHECK_RANGE:
		/* Block all other known PSCI calls. */
		*ret = PSCI_ERROR_NOT_SUPPORTED;
		break;

	default:
		return false;
	}

	return true;
}

/**
 * Handles PSCI requests received via HVC or SMC instructions from a VM.
 * Requests from primary and secondary VMs are dealt with differently.
 *
 * Returns true if the request was a PSCI one, false otherwise.
 */
bool psci_handler(struct vcpu *vcpu, uint32_t func, uintreg_t arg0,
		  uintreg_t arg1, uintreg_t arg2, uintreg_t *ret,
		  struct vcpu **next)
{
	if (vm_is_primary(vcpu->vm)) {
		return psci_primary_vm_handler(vcpu, func, arg0, arg1, arg2,
					       ret);
	}
	return psci_secondary_vm_handler(vcpu, func, arg0, arg1, arg2, ret,
					 next);
}
