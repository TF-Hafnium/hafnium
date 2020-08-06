/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "primary_with_secondary.h"
#include "sysregs.h"
#include "test/vmapi/ffa.h"

/**
 * QEMU does not properly handle the trapping of certain system register
 * accesses. This was fixed in a custom local build that we could use. If not
 * using that build, limit testing to the subset QEMU handles correctly.
 */
#define CUSTOM_QEMU_BUILD() 0

TEAR_DOWN(debug_el1)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

TEST(debug_el1, secondary_basic)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "debug_el1_secondary_basic", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Attempts to access debug registers for read, without validating their value.
 */
TEST(debug_el1, primary_basic)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);

	if (CUSTOM_QEMU_BUILD()) {
		TRY_READ(DBGAUTHSTATUS_EL1);
		TRY_READ(DBGCLAIMCLR_EL1);
		TRY_READ(DBGCLAIMSET_EL1);
		TRY_READ(DBGPRCR_EL1);
		TRY_READ(OSDTRRX_EL1);
		TRY_READ(OSDTRTX_EL1);
		TRY_READ(OSECCR_EL1);

		TRY_READ(DBGBCR2_EL1);
		TRY_READ(DBGBCR3_EL1);
		TRY_READ(DBGBCR4_EL1);
		TRY_READ(DBGBCR5_EL1);
		TRY_READ(DBGBVR2_EL1);
		TRY_READ(DBGBVR3_EL1);
		TRY_READ(DBGBVR4_EL1);
		TRY_READ(DBGBVR5_EL1);
		TRY_READ(DBGWCR2_EL1);
		TRY_READ(DBGWCR3_EL1);
		TRY_READ(DBGWVR2_EL1);
		TRY_READ(DBGWVR3_EL1);
	}

	/* The following is the subset currently supported by QEMU. */
	TRY_READ(MDCCINT_EL1);
	TRY_READ(MDRAR_EL1);
	TRY_READ(MDSCR_EL1);
	TRY_READ(OSDLR_EL1);
	TRY_READ(OSLSR_EL1);

	TRY_READ(DBGBCR0_EL1);
	TRY_READ(DBGBCR1_EL1);
	TRY_READ(DBGBVR0_EL1);
	TRY_READ(DBGBVR1_EL1);
	TRY_READ(DBGWCR0_EL1);
	TRY_READ(DBGWCR1_EL1);
	TRY_READ(DBGWVR0_EL1);
	TRY_READ(DBGWVR1_EL1);
}

/**
 * Tests a few debug registers for read and write, and checks that the expected
 * value is written/read.
 */
TEST(debug_el1, primary_read_write)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);

	CHECK_UPDATE(DBGBCR0_EL1, 0x0, 0x2);
	CHECK_UPDATE(DBGBVR0_EL1, 0xc4, 0xf0);
}
