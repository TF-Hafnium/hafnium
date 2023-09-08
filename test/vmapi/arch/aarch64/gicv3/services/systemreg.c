/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/events.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/timer.h"

#include "hf/dlog.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"

/*
 * Secondary VM that tries to access GICv3 system registers.
 */

TEST_SERVICE(access_systemreg_ctlr)
{
	exception_setup(NULL, exception_handler_skip_instruction);

	/* Reading ICC_CTLR_EL1 should trap the VM. */
	read_msr(ICC_CTLR_EL1);

	/* Writing ICC_CTLR_EL1 should trap the VM. */
	write_msr(ICC_CTLR_EL1, 0);

	EXPECT_EQ(exception_handler_get_num(), 2);

	/* Yield after catching the exceptions. */
	ffa_yield();
}

TEST_SERVICE(write_systemreg_sre)
{
	uintreg_t read;

	exception_setup(NULL, exception_handler_skip_instruction);

	read = read_msr(ICC_SRE_EL1);
	if (exception_handler_get_num() != 0) {
		/* If reads are trapped then writes should also be trapped. */
		ASSERT_EQ(exception_handler_get_num(), 1);
		write_msr(ICC_SRE_EL1, 0x0);
		ASSERT_EQ(exception_handler_get_num(), 2);
	} else {
		ASSERT_EQ(read, 0x7);
		/* Writing ICC_SRE_EL1 should be ignored. */
		write_msr(ICC_SRE_EL1, 0x0);
		ASSERT_EQ(read_msr(ICC_SRE_EL1), 0x7);
		write_msr(ICC_SRE_EL1, 0xffffffff);
		ASSERT_EQ(read_msr(ICC_SRE_EL1), 0x7);
	}

	ffa_yield();
}
