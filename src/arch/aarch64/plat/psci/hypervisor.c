/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"
#include "hf/dlog.h"

#include "psci.h"

static uint32_t el3_psci_version;

/**
 * Returns the PSCI version gathered from the EL3 PSCI layer during init.
 */
uint32_t plat_psci_version_get(void)
{
	return el3_psci_version;
}

/**
 * Initialize the platform power managment module in context of
 * running the Hypervisor. In particular it gathers the PSCI version
 * from the EL3 PSCI firmware.
 */
void plat_psci_init(void)
{
	struct ffa_value smc_res =
		smc32(PSCI_VERSION, 0, 0, 0, 0, 0, 0, SMCCC_CALLER_HYPERVISOR);

	el3_psci_version = smc_res.func;

	/* Check there's nothing unexpected about PSCI. */
	switch (el3_psci_version) {
	case PSCI_VERSION_0_2:
	case PSCI_VERSION_1_0:
	case PSCI_VERSION_1_1:
		/* Supported EL3 PSCI version. */
		dlog_info("Found PSCI version: %#x\n", el3_psci_version);
		break;

	default:
		/* Unsupported EL3 PSCI version. Log a warning but continue. */
		dlog_warning("Unknown PSCI version: %#x\n", el3_psci_version);
		el3_psci_version = 0;
		break;
	}
}

void plat_psci_cpu_suspend(uint32_t power_state)
{
	(void)power_state;
}

void plat_psci_cpu_resume(void)
{
}
