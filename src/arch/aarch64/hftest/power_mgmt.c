/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "vmapi/hf/call.h"

#include "psci.h"
#include "smc.h"

/**
 * Starts the CPU with the given ID. It will set the stack pointer according to
 * the provided `state` and jump to the entry point with the given argument
 * specified in it.
 *
 * Note: The caller of this function must guarantee that the contents of `state`
 * do not change until the new CPU has branched to the given entry point, and
 * that it was written-back to memory (that it is not waiting in a data cache)
 * because the new CPU is started with caching disabled.
 */
bool arch_cpu_start(uintptr_t id, struct arch_cpu_start_state *state)
{
	void vm_cpu_entry(uintptr_t arg);
	struct ffa_value smc_res;

	/* Try to start the CPU. */
	smc_res = smc64(PSCI_CPU_ON, id, (uintptr_t)&vm_cpu_entry,
			(uintptr_t)state, 0, 0, 0, SMCCC_CALLER_HYPERVISOR);

	return smc_res.func == PSCI_RETURN_SUCCESS;
}

/**
 * Stops the current CPU.
 */
[[noreturn]] void arch_cpu_stop(void)
{
	smc32(PSCI_CPU_OFF, 0, 0, 0, 0, 0, 0, SMCCC_CALLER_HYPERVISOR);
	for (;;) {
		/* This should never be reached. */
	}
}

static_assert((uint32_t)POWER_STATUS_ON == (uint32_t)PSCI_RETURN_ON,
	      "power_status enum values must match PSCI return values.");
static_assert((uint32_t)POWER_STATUS_OFF == (uint32_t)PSCI_RETURN_OFF,
	      "power_status enum values must match PSCI return values.");
static_assert((uint32_t)POWER_STATUS_ON_PENDING ==
		      (uint32_t)PSCI_RETURN_ON_PENDING,
	      "power_status enum values must match PSCI return values.");

/**
 * Returns the power status of the given CPU.
 */
enum power_status arch_cpu_status(cpu_id_t cpu_id)
{
	uint32_t lowest_affinity_level = 0;
	struct ffa_value smc_res;

	/*
	 * This works because the power_status enum values happen to be the same
	 * as the PSCI_RETURN_* values. The static_asserts above validate that
	 * this is the case.
	 */
	smc_res = smc32(PSCI_AFFINITY_INFO, cpu_id, lowest_affinity_level, 0, 0,
			0, 0, SMCCC_CALLER_HYPERVISOR);
	return smc_res.func;
}

/**
 * Shuts down the system or exits emulation.
 */
[[noreturn]] void arch_power_off(void)
{
	smc32(PSCI_SYSTEM_OFF, 0, 0, 0, 0, 0, 0, SMCCC_CALLER_HYPERVISOR);
	for (;;) {
		/* This should never be reached. */
	}
}

/**
 * Restarts the system.
 */
[[noreturn]] void arch_reboot(void)
{
	smc32(PSCI_SYSTEM_RESET, 0, 0, 0, 0, 0, 0, SMCCC_CALLER_HYPERVISOR);
	for (;;) {
		/* This should never be reached. */
	}
}
