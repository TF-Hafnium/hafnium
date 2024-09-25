/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define PAGE_BITS 12
#define PAGE_LEVEL_BITS 9
#define STACK_ALIGN 64

/** The type of a page table entry (PTE). */
typedef uint64_t pte_t;

/** Integer type large enough to hold a physical address. */
typedef uintptr_t uintpaddr_t;

/** Integer type large enough to hold a virtual address. */
typedef uintptr_t uintvaddr_t;

/** The integer corresponding to the native register size. */
typedef uint64_t uintreg_t;

/** The ID of a physical or virtual CPU. */
typedef uint32_t cpu_id_t;

/**
 * Data structure to represent a fake timer peripheral. It has two registers:
 * - a decrementing counter value and
 * - a control register.
 */
struct timer_state {
	uintreg_t cval;
	uintreg_t ctl;
};

/** Type to represent the register state of a VM. */
struct arch_regs {
	uintreg_t arg[8];
	cpu_id_t vcpu_id;
	bool virtual_interrupt;
	struct timer_state arch_timer;
};

/** Type of interrupts */
enum interrupt_type {
	INTERRUPT_TYPE_IRQ,
};
