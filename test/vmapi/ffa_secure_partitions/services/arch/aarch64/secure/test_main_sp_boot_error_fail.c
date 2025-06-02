/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/**
 * This function is used in test setups that test error handling
 * for an SP failing to initialize.
 * SP reports a failure during initialization by calling FFA_ERROR
 * instead of FFA_MSG_WAIT.
 */
#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

void test_main_sp(bool is_boot_vcpu)
{
	(void)is_boot_vcpu;
	ffa_call((struct ffa_value){.func = FFA_ERROR_32, .arg2 = FFA_ABORTED});
}
