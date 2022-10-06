/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "pauth_macros.S"

.section .init.image_entry, "ax"
.global image_entry
image_entry:
	/* Prepare the stack. */
	adrp x30, kstack
	add sp, x30, #4096

	/* Disable trapping floating point access in EL1. */
	mov x30, #(0x3 << 20)
	msr cpacr_el1, x30
	isb

#if BRANCH_PROTECTION
	mrs x1, id_aa64isar1_el1
	ands x1, x1, #0xff0		/* API / APA */
	b.eq 0f

	enable_pauth_el1 x30 39
#endif
	/* Call into C code. */
0:	bl kmain

	/* If the VM returns, shutdown the system. */
	bl arch_power_off

	/* Loop forever waiting for interrupts. */
1:	wfi
	b 1b
