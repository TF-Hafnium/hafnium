/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.section .init.image_entry, "ax"
.global image_entry
image_entry:
	/* Prepare the stack. */
	adr x30, kstack + 4096
	mov sp, x30

	/* Call into C code. */
	bl el0_main

	/* Loop forever waiting for interrupts. */
0:	wfi
	b 0b
