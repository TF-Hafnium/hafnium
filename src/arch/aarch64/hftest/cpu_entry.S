/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "pauth_macros.S"

.global vm_cpu_entry
vm_cpu_entry:
	/* Disable trapping floating point access in EL1. */
	mov x1, #(0x3 << 20)
	msr cpacr_el1, x1
	isb

#if BRANCH_PROTECTION
	mrs x1, id_aa64isar1_el1
	ands x1, x1, #0xff0		/* API / APA */
	b.eq 0f
	enable_pauth_el1 x30 39
#endif
	/* Initialise stack from the cpu_start_state struct. */
0:	ldr x1, [x0]
	mov sp, x1

	/* Load entry function pointer and its argument. */
	ldr x1, [x0, 8]
	ldr x0, [x0, 16]

	/* Branch to entry function. */
	blr x1

	/* Entry function should not return, but if it does, spin. */
	b .
