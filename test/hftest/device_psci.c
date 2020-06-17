/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "test/hftest.h"

noreturn void hftest_device_reboot(void)
{
	arch_reboot();
}

void hftest_device_exit_test_environment(void)
{
	HFTEST_LOG("%s not supported", __func__);
}
