/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"
#include "hf/dlog.h"

#include "psci.h"

/**
 * Returns zero in context of the SPMC as it does not rely
 * on the EL3 PSCI framework.
 */
uint32_t plat_psci_version_get(void)
{
	return 0;
}

/**
 * Initialize the platform power managment module in context of
 * running the SPMC.
 */
void plat_psci_init(void)
{
}

void plat_psci_cpu_suspend(uint32_t power_state)
{
	(void)power_state;
}

void plat_psci_cpu_resume(struct cpu *c, ipaddr_t entry_point)
{
	(void)c;
	(void)entry_point;
}
