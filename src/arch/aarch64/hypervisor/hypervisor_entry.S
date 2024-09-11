/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/offsets.h"
#include "hf/cpu.h"
#include "msr.h"

.macro get_core_affinity reg1 reg2
	mrs \reg1, mpidr_el1
	ubfx \reg2, \reg1, 0, 24
	ubfx \reg1, \reg1, 32, 8
	orr \reg1, \reg2, \reg1, lsl #32
.endm

.macro init_stack_zero_tag
#if ENABLE_MTE
	mov x1, sp
	sub x2, x1, #STACK_SIZE
	/* Assume 16 bytes tag granule size. */
0:	stz2g x2, [x2], #32
	cmp x2, x1
	bne 0b
#endif
.endm

.macro check_supported_pauth_alg
	/* Expect pointer authentication is implemented. */
	mrs	x1, id_aa64isar1_el1
	and	x1, x1, #0xff0		/* API / APA */
	mrs	x2, id_aa64isar2_el1
	and	x2, x2, #0xf000		/* APA3 */
	orr	x1, x1, x2
	cmp	x1, #0
	beq	.
.endm


/**
 * Called only on first boot after the image has been relocated and BSS zeroed.
 *
 * It is required that caches be clean and invalid.
 */
.section .init.image_entry, "ax"
.global image_entry
image_entry:
	/* Interpret the registers passed from the loader. */
	bl plat_boot_flow_hook

	/* Get pointer to first CPU. */
	adrp x28, cpus
	add x28, x28, :lo12:cpus

	/* Set the ID of this CPU from the affinity bits of mpidr. */
	get_core_affinity x30, x29
	str x30, [x28, CPU_ID]

#if SECURE_WORLD == 1

	/*
	 * Invalidate the data cache for the whole image.
	 * This prevents re-use of stale data cache entries from
	 * prior bootloader stages.
	 */
	adrp x0, ORIGIN_ADDRESS
	adrp x1, image_end
	sub x1, x1, x0
	bl arch_cache_data_invalidate_range

#endif

	mov x0, x28
	bl prepare_for_c

	/* Initialization of the stack guard by a random value */
	bl stack_protector_init

	/*
	 * Call into C to initialize the memory management configuration with
	 * MMU and caches disabled. Result will be stored in `arch_mm_config`.
	 */
	bl one_time_init_mm

#if BRANCH_PROTECTION
	check_supported_pauth_alg

	/* Gather a random number to use as pointer authentication key. */
	bl	plat_prng_get_number
	adrp	x3, pauth_apia_key
	add	x2, x3, :lo12: pauth_apia_key
	stp	x0, x1, [x2]
#endif

#if ENABLE_MTE
	/* Expect at least MTE level 2. */
	mrs	x1, id_aa64pfr1_el1
	ubfx	x1, x1, #8, #4
	cmp	x1, #2
	bcc	.

	/* Get a random number to use as a seed for MTE tags. */
	bl 	plat_prng_get_number
	# Mask random RGSR_EL1 seed and tag field.
	lsr	w0, w0, #8
	bic	w0, w0, #0xf0
	adrp	x2, mte_seed
	add	x2, x2, :lo12: mte_seed
	str	x0, [x2]
	msr	rgsr_el1, x0
	msr	gcr_el1, xzr
#endif

	/* Enable MMU and caches before running the rest of initialization. */
	bl mm_enable

	init_stack_zero_tag

	bl one_time_init

	/* Begin steady state operation. */
	mov x0, x28
	b cpu_init

/**
 * Entry point for all cases other than the first boot e.g. secondary CPUs and
 * resuming from suspend.
 *
 * It is required that caches be coherent but not necessarily clean or invalid.
 *
 * x0 points to the current CPU.
 */
.section .text.entry, "ax"
.global cpu_entry
cpu_entry:
#if SECURE_WORLD == 1

	/* Get number of cpus gathered from DT. */
	adrp x3, cpu_count
	add x3, x3, :lo12:cpu_count
	ldr w3, [x3]

	/* Prevent number of CPUs to be higher than supported by platform. */
	cmp w3, #MAX_CPUS
	bhi .

	/* x0 points to first cpu in cpus array. */
	adrp x0, cpus
	add x0, x0, :lo12:cpus

	/* Get current core affinity. */
	get_core_affinity x1, x2

	/* Dead stop here if no more cpu. */
0:	cbz w3, 0b

	sub w3, w3, #1

	/* Get cpu id pointed to by x0 in cpu array. */
	ldr x2, [x0, CPU_ID]

	/* Exit if current core id matches cpu id. */
	cmp x1, x2
	beq 1f

	/* Point to next cpu in cpus array and loop. */
	add x0, x0, #CPU_SIZE
	b 0b

1:	/* x0 points to current cpu in cpus array */

#endif

#if BRANCH_PROTECTION
	check_supported_pauth_alg
#endif

#if ENABLE_MTE
	/* Expect at least MTE level 2. */
	mrs	x1, id_aa64pfr1_el1
	ubfx	x1, x1, #8, #4
	cmp	x1, #2
	bcc	.

	/* Feed previously generated MTE seed. */
	adrp	x2, mte_seed
	add	x2, x2, :lo12: mte_seed
	ldr	x1, [x2]
	msr	rgsr_el1, x1
	# GCR_EL1.RRND=0: IRG generates a tag value as defined by RandomTag()
	# GCR_EL1.Exclude=0x0000: none of allocation tag is excluded
	msr	gcr_el1, xzr
#endif

	bl mm_enable
	bl prepare_for_c

	init_stack_zero_tag

	/* Intentional fallthrough. */

cpu_init:
	/* Call into C code, x0 holds the CPU pointer. */
	bl cpu_main

	/* Run the vCPU returned by cpu_main. */
	bl vcpu_restore_all_and_run

	/* Loop forever waiting for interrupts. */
0:	wfi
	b 0b

/**
 * Set up CPU environment for executing C code. This is called on first boot
 * with caches disabled but subsequent calls will have caches enabled.
 *
 * x0 points to the current CPU on entry and exit.
 */
prepare_for_c:
	/* Use SPx (instead of SP0). */
	msr spsel, #1

	/* Prepare the stack. */
	ldr x1, [x0, #CPU_STACK_BOTTOM]
	mov sp, x1

	/* Configure exception handlers. */
	adr x2, vector_table_el2
	msr vbar_el2, x2
	ret

/**
 * Applies the memory management configuration to the CPU, preserving x0 along
 * the way.
 */
mm_enable:
	/*
	 * Invalidate any potentially stale local TLB entries for the
	 * hypervisor's stage-1 and the VM's stage-2 before they start being
	 * used. The VM's stage-1 is invalidated as a side effect but it wasn't
	 * using it yet anyway.
	 */
	tlbi alle2
	tlbi vmalls12e1

	/*
	 * Load and apply the memory management configuration. Order depends on
	 * `struct arch_mm_config.
	 */
	adrp x7, arch_mm_config
	add x7, x7, :lo12:arch_mm_config

	ldp x1, x2, [x7]	/* x1: ttbr0_el2, x2: mair_el2 */
	ldp x3, x4, [x7, #16]	/* x3: tcr_el2, x4: sctlr_el2 */
	ldp x5, xzr, [x7, #32]	/* x5: hcr_el2 */

	/*
	 * Set hcr_el2 before tcr_el2, since hcr_el2.e2h may be set, which changes
	 * the definition of tcr_el2.
	 */
	msr hcr_el2, x5
	isb

	msr ttbr0_el2, x1

	msr mair_el2, x2
	msr tcr_el2, x3

	/* Ensure everything before this point has completed. */
	dsb sy
	isb

#if BRANCH_PROTECTION
	/* Load EL2 APIA Key. */
	adrp	x1, pauth_apia_key
	add	x1, x1, :lo12: pauth_apia_key
	ldp	x1, x2, [x1]
	msr     APIAKEYLO_EL1, x1
	msr     APIAKEYHI_EL1, x2

	/*
	 * Emit ISB to ensure the pointer authentication key change takes
	 * effect before any pauth instruction is executed.
	 */
	isb
#endif

	/*
	 * Configure sctlr_el2 to enable MMU and cache and don't proceed until
	 * this has completed.
	 */
	msr sctlr_el2, x4
	isb
	ret
