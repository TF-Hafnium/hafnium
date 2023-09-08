/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"

#include "../sysregs.h"
#include "test/vmapi/arch/exception_handler.h"

TEST_SERVICE(debug_el1_secondary_basic)
{
	exception_setup(NULL, exception_handler_skip_instruction);

	EXPECT_GT(hf_vm_get_id(), HF_PRIMARY_VM_ID);
	TRY_READ(MDCCINT_EL1);
	TRY_READ(DBGBCR0_EL1);
	TRY_READ(DBGBVR0_EL1);
	TRY_READ(DBGWCR0_EL1);
	TRY_READ(DBGWVR0_EL1);

	EXPECT_EQ(exception_handler_get_num(), 5);
	ffa_yield();
}
