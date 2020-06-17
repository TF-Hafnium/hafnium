/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/psci.h"

void plat_psci_cpu_suspend(uint32_t power_state)
{
	(void)power_state;
}

void plat_psci_cpu_resume(void)
{
}
