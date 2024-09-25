/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdalign.h>
#include <stdint.h>

#include "hf/ffa.h"
#include "hf/static_assert.h"

#define PAGE_BITS 12
#define PAGE_LEVEL_BITS 9
#define STACK_ALIGN 16
#define FLOAT_REG_BYTES 16
#define NUM_GP_REGS 31

/** The type of a page table entry (PTE). */
typedef uint64_t pte_t;

/** Integer type large enough to hold a physical address. */
typedef uintptr_t uintpaddr_t;

/** Integer type large enough to hold a virtual address. */
typedef uintptr_t uintvaddr_t;

/** The integer type corresponding to the native register size. */
typedef uint64_t uintreg_t;

/** The ID of a physical or virtual CPU. */
typedef uint64_t cpu_id_t;

/** A bitset for AArch64 CPU features. */
typedef uint64_t arch_features_t;

/**
 * The struct for storing a floating point register.
 *
 * 2 64-bit integers used to avoid need for FP support at this level.
 */
struct float_reg {
	alignas(FLOAT_REG_BYTES) uint64_t low;
	uint64_t high;
};

static_assert(sizeof(struct float_reg) == FLOAT_REG_BYTES,
	      "Ensure float register type is 128 bits.");

/** Timer CompareValue and control registers. */
struct timer_state {
	uintreg_t cval;
	uintreg_t ctl;
};

/** Type to represent the register state of a vCPU. */
struct arch_regs {
	/* General purpose registers. */
	uintreg_t r[NUM_GP_REGS];
	uintreg_t pc;
	uintreg_t spsr;

	/* Hypervisor configuration while a vCPU runs. */
	struct {
		uintreg_t hcr_el2;
		uintreg_t ttbr0_el2;
		uintreg_t sctlr_el2;
		uintreg_t cptr_el2;
	} hyp_state;

	/*
	 * System registers.
	 * NOTE: Ordering is important. If adding to or reordering registers
	 * below, make sure to update src/arch/aarch64/hypervisor/exceptions.S.
	 * Registers affected by VHE are grouped together followed by other
	 * registers.
	 *
	 */
	struct {
		uintreg_t sctlr_el1; /* Start VHE affected registers */
		uintreg_t cpacr_el1;
		uintreg_t ttbr0_el1;
		uintreg_t ttbr1_el1;
		uintreg_t tcr_el1;
		uintreg_t esr_el1;
		uintreg_t afsr0_el1;
		uintreg_t afsr1_el1;
		uintreg_t far_el1;
		uintreg_t mair_el1;
		uintreg_t vbar_el1;
		uintreg_t contextidr_el1;
		uintreg_t amair_el1;
		uintreg_t cntkctl_el1;
		uintreg_t elr_el1;
		uintreg_t spsr_el1; /* End VHE affected registers */

		uintreg_t vmpidr_el2;
		uintreg_t csselr_el1;
		uintreg_t actlr_el1;
		uintreg_t tpidr_el0;
		uintreg_t tpidrro_el0;
		uintreg_t tpidr_el1;
		uintreg_t sp_el0;
		uintreg_t sp_el1;
		uintreg_t vtcr_el2;
		uintreg_t vttbr_el2;
		uintreg_t vstcr_el2;
		uintreg_t vsttbr_el2;
		uintreg_t mdcr_el2;
		uintreg_t mdscr_el1;
		uintreg_t pmccfiltr_el0;
		uintreg_t pmcr_el0;
		uintreg_t pmcntenset_el0;
		uintreg_t pmintenset_el1;
		uintreg_t cnthctl_el2;
		uintreg_t par_el1;
	} lazy;

	/* Floating point registers. */
	struct float_reg fp[32];
	uintreg_t fpsr;
	uintreg_t fpcr;

#if GIC_VERSION == 3 || GIC_VERSION == 4
	struct {
		uintreg_t ich_hcr_el2;
		uintreg_t icc_sre_el2;
	} gic;
#endif

	/*
	 * Timer registers, handled separately from other system registers.
	 */
	struct timer_state arch_timer;

#if BRANCH_PROTECTION
	/* Pointer authentication keys */
	struct {
		uintreg_t apiakeylo_el1;
		uintreg_t apiakeyhi_el1;
		uintreg_t apibkeylo_el1;
		uintreg_t apibkeyhi_el1;
		uintreg_t apdakeylo_el1;
		uintreg_t apdakeyhi_el1;
		uintreg_t apdbkeylo_el1;
		uintreg_t apdbkeyhi_el1;
		uintreg_t apgakeylo_el1;
		uintreg_t apgakeyhi_el1;
	} pac;
#endif

#if ENABLE_MTE
	/* MTE registers. */
	struct {
		uintreg_t tfsr_el1;
		uintreg_t gcr_el1;
		uintreg_t rgsr_el1;
		uintreg_t tfsre0_el1;
	} mte;
#endif
};

/** Type of interrupts */
enum interrupt_type {
	INTERRUPT_TYPE_IRQ,
	INTERRUPT_TYPE_FIQ,
};
