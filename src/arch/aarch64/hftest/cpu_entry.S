/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.global vm_cpu_entry
vm_cpu_entry:
	/* Disable trapping floating point access in EL1. */
	mov x1, #(0x3 << 20)
	msr cpacr_el1, x1
	isb

	/* Initialise stack from the cpu_start_state struct. */
	ldr x1, [x0]
	mov sp, x1

	/* Load entry function pointer and its argument. */
	ldr x1, [x0, 8]
	ldr x0, [x0, 16]

	/* Branch to entry function. */
	blr x1

	/* Entry function should not return, but if it does, spin. */
	b .
