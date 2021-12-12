/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.macro ffa_mem_perm_set start:req end:req perm:req
	adrp x29, \start
	add x29, x29, :lo12: \start

	adrp x30, \end
	add x30, x30, :lo12:\end

	/* x30 = end - begin */
	sub x30, x30, x29
	/* x28 = x30 >> 12 (number of pages) */
	mov x28, #12
	lsrv x28, x30, x28

	/* 0x84000089 is function identifier for FFA_MEM_PERM_SET_32 */
	mov w0, #0x89
	movk w0, #0x8400, lsl #16
	mov x1, x29
	mov x2, x28
	mov w3, #\perm

	svc #0

	/* 0x84000061 is function identifier for FFA_SUCCESS_32 */
	mov w1, #0x61
	movk w1, #0x8400, lsl #16
	cmp w1, w0
	b.ne .
.endm

.section .init.entry, "ax"
.global entry
entry:
	/* Linux aarch64 image header. */
	b 0f
	.word 0
	.quad 0x1000      /* text_offset */
	.quad image_size  /* image_size */
	.quad 0           /* flags */
	.quad 0           /* res2 */
	.quad 0           /* res3 */
	.quad 0           /* res4 */
	.word 0x644d5241  /* magic */
	.word 0

0:
	/* Save data (fdt pointer or mem size) passed by hypervisor. */
	mov x10, x0

	/* Set everything other than text as RW, so that relocations can succeed. */
	ffa_mem_perm_set rodata_begin image_end 5

	/*
	 * Calculate the difference between the actual load address and the
	 * preferred one. We'll use this to relocate.
	 */
	adrp x25, entry
	add x25, x25, :lo12:entry

	ldr w29, =ORIGIN_ADDRESS

	sub x25, x25, x29

	/* Find where the relocations begin and end. */
	adrp x29, rela_begin
	add x29, x29, :lo12:rela_begin

	adrp x30, rela_end
	add x30, x30, :lo12:rela_end

	/* Iterate over all relocations. */
1:	cmp x29, x30
	b.eq 2f

	ldp x26, x27, [x29], #16
	ldr x28, [x29], #8

	cmp w27, #1027 /* R_AARCH64_RELATIVE */
	b.ne .

	add x28, x28, x25
	str x28, [x26, x25]
	b 1b

	/* Set everything between ro data and data begin as RO */
2:	ffa_mem_perm_set rodata_begin data_begin 7

	/* set everthing else as RW */
	ffa_mem_perm_set data_begin image_end 5

	/* Zero out the bss section. */
	adrp x29, bss_begin
	add x29, x29, :lo12:bss_begin

	adrp x30, bss_end
	add x30, x30, :lo12:bss_end

3:	cmp x29, x30
	b.hs 4f

	stp xzr, xzr, [x29], #16
	b 3b

4:	mov x0, x10

	/* Branch to the entry point for the specific image. */
	b image_entry

.section .init.image_entry, "ax"
.global image_entry
image_entry:
	/* Prepare the stack. */
	adr x30, kstack + 4096
	mov sp, x30

	/* Call into C code. */
	bl kmain

	/* Loop forever waiting for interrupts. */
0:	wfi
	b 0b
