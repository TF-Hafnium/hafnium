/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "msr.h"

/*
 * Enable Pointer Authentication at EL1 given scratch register
 * reg1 and value of T0SZ (The size offset of the memory region
 * addressed by TTBR0_EL1).
*/
.macro enable_pauth_el1 reg1 t0sz
	/* Initialize pointer authentication key to arbitrary value. */
	mov \reg1, #1842
	msr APIAKEYLO_EL1, \reg1
	msr APIAKEYHI_EL1, \reg1

	/* Enable PAuth using APIAKey_EL1 key */
	mrs \reg1, sctlr_el1
	orr \reg1, \reg1, #(1 << 31)
	msr sctlr_el1, \reg1

	mov \reg1, #(64 - \t0sz)
	msr tcr_el1, \reg1
	isb
.endm
