/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static void pauth_fault_helper(void)
{
	FAIL("This should not be called\n");
}

/**
 * Trigger a Pointer Authentication Fault in an S-EL0 partition.
 */
void sp_pauth_fault_cmd(void)
{
	uintptr_t bad_addr = (uintptr_t)&pauth_fault_helper;

	HFTEST_LOG("bad_addr: %lx", (uint64_t)bad_addr);

	/* Overwrite LR and trigger PAuth Fault exception. */
	__asm__("mov x17, x30; "
		"mov x30, %0; "	      /* Overwite LR. */
		"add sp, sp, #0x30; " /* Revert SP to value at entrance to
					 function (when PAC is generated). */
		"isb; "
		"autiasp; "
		"sub sp, sp, #0x30; " /* Restore SP. */
		"ret; "		      /* Fault on return.  */
		"end: "
		:
		: "r"(bad_addr));

	/*
	 * S-EL0 partition will be aborted on Pointer Authentication fault and
	 * should not reach this point.
	 */
	FAIL("Faulting partition should have been aborted by SPMC\n");
}
