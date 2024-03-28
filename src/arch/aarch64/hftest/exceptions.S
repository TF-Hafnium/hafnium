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

restore_from_stack_and_return el1

exception_handler_return:
	eret_with_sb
