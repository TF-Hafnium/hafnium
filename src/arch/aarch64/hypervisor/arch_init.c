/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/plat/psci.h"

/**
 * Performs arch specific boot time initialization.
 */
void arch_one_time_init(void)
{
	plat_psci_init();
}
