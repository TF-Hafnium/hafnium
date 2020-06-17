/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "exception_macros.S"

.section .text.vector_table_el1, "ax"
.global vector_table_el1
.balign 0x800
vector_table_el1:
sync_cur_sp0:
	b .

.balign 0x80
irq_cur_sp0:
	current_exception_sp0 el1 irq_current exception_handler_return

.balign 0x80
fiq_cur_sp0:
	b .

.balign 0x80
serr_cur_sp0:
	b .

.balign 0x80
sync_cur_spx:
	current_exception_spx el1 sync_exception_current

.balign 0x80
irq_cur_spx:
	current_exception_spx el1 irq_current

.balign 0x80
fiq_cur_spx:
	b .

.balign 0x80
serr_cur_spx:
	b .

.balign 0x80
sync_lower_64:
	b .

.balign 0x80
irq_lower_64:
	b .

.balign 0x80
fiq_lower_64:
	b .

.balign 0x80
serr_lower_64:
	b .

.balign 0x80
sync_lower_32:
	b .

.balign 0x80
irq_lower_32:
	b .

.balign 0x80
fiq_lower_32:
	b .

.balign 0x80
serr_lower_32:
	b .

.balign 0x40
/**
 * Restores the volatile registers from the stack.

 * Register x0: if false restores elr_el1, if true retains the value of elr_el1.
 * This enables exception handlers to indicate whether they have changed the
 * value of elr_el1 (e.g., to skip the faulting instruction).
 */
restore_from_stack_and_return:
	/* Restore registers x2-x18, x29 & x30. */
	ldp x2, x3, [sp, #8 * 2]
	ldp x4, x5, [sp, #8 * 4]
	ldp x6, x7, [sp, #8 * 6]
	ldp x8, x9, [sp, #8 * 8]
	ldp x10, x11, [sp, #8 * 10]
	ldp x12, x13, [sp, #8 * 12]
	ldp x14, x15, [sp, #8 * 14]
	ldp x16, x17, [sp, #8 * 16]
	ldr x18, [sp, #8 * 18]
	ldp x29, x30, [sp, #8 * 20]

	cbnz x0, skip_elr

	/* Restore register elr_el1 using x1 as scratch. */
	ldr x1, [sp, #8 * 22]
	msr elr_el1, x1

skip_elr:
	/* Restore register spsr_el1 using x1 as scratch. */
	ldr x1, [sp, #8 * 23]
	msr spsr_el1, x1

	/* Restore x0 & x1, and release stack space. */
	ldp x0, x1, [sp], #8 * 24

exception_handler_return:
	eret_with_sb
