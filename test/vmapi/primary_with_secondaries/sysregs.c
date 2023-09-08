/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "sysregs.h"

#include "hf/arch/vm/interrupts.h"

#include "primary_with_secondary.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

SET_UP(sysregs)
{
	exception_setup(NULL, exception_handler_skip_instruction);
}

/**
 * Test that accessing LOR registers would inject an exception.
 */
TEST(sysregs, lor_exception)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);
	TRY_READ(MSR_LORC_EL1);

	EXPECT_EQ(exception_handler_get_num(), 1);
}
