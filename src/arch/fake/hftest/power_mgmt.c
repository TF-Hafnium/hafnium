/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include <sys/reboot.h>

noreturn void arch_power_off(void)
{
	reboot(RB_POWER_OFF);
	for (;;) {
		/* This should never be reached. */
	}
}
