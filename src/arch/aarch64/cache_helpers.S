/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/**
 * Macros and functions imported from TF-A project:
 * https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git/tree/include/arch/aarch64/asm_macros.S?h=v2.4
 * https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git/tree/lib/aarch64/cache_helpers.S?h=v2.4
 */

.macro	dcache_line_size  reg, tmp
	mrs	\tmp, ctr_el0
	ubfx	\tmp, \tmp, #16, #4
	mov	\reg, #4
	lsl	\reg, \reg, \tmp
.endm

/*
 * This macro can be used for implementing various data cache operations `op`
 */
.macro do_dcache_maintenance_by_mva op
	/* Exit early if size is zero */
	cbz	x1, exit_loop_\op
	dcache_line_size x2, x3
	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
loop_\op:
	dc	\op, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	loop_\op
	dsb	sy
exit_loop_\op:
	ret
.endm

/**
 * ------------------------------------------
 * Invalidate from base address till
 * size. 'x0' = addr, 'x1' = size
 * ------------------------------------------
 */
.globl arch_cache_data_invalidate_range
arch_cache_data_invalidate_range:
	do_dcache_maintenance_by_mva ivac

/**
 * ------------------------------------------
 * Clean from base address till size.
 * 'x0' = addr, 'x1' = size
 * ------------------------------------------
 */
.globl arch_cache_data_clean_range
arch_cache_data_clean_range:
	do_dcache_maintenance_by_mva cvac
