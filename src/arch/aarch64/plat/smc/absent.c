/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/smc.h"

void plat_smc_post_forward(struct spci_value args, struct spci_value *ret)
{
	(void)args;
	(void)ret;
}
