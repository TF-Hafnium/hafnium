/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.section .init.image_entry, "ax"
.global secondary_ep_entry
secondary_ep_entry:
	/*
	 * Prepare the stack for core.
	 * The mpdir_el1 register contains the linear ID.
	 */
	mrs x29, mpidr_el1
	ubfx x29, x29, #0, #30
	mov x27, #4096
	mul x27, x29, x27
	adrp x30, kstack
	add sp, x30, x27

	/* Disable trapping floating point access in EL1. */
	mov x30, #(0x3 << 20)
	msr cpacr_el1, x30
	isb

	/* Enable MMU and cache. */
	bl hftest_mm_vcpu_init

	/* Branch to message loop hinting a secondary vCPU. */
	mov x0, xzr
	b test_main_sp
