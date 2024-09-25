/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#define STACK_SIZE (8192)

#ifndef __ASSEMBLER__

#include "hf/arch/cpu.h"

#include "hf/timer_mgmt.h"

/* TODO: Fix alignment such that `cpu` structs are in different cache lines. */
/* NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding) */
struct cpu {
	/** CPU identifier. Doesn't have to be contiguous. */
	cpu_id_t id;

	/** Pointer to bottom of the stack. */
	void *stack_bottom;

	/** See api.c for the partial ordering on locks. */
	struct spinlock lock;

	/** Determines whether the CPU is currently on. */
	bool is_on;

	/* In case there is a pending SRI for the NWd. */
	bool is_sri_delayed;

	/* Track pending IPIs. */
	struct vcpu *ipi_target_vcpu;

	/**
	 * A list of entries associated with vCPUs having pending timer
	 * deadline.
	 */
	struct timer_pending_vcpu_list pending_timer_vcpus_list;
};

void cpu_module_init(const cpu_id_t *cpu_ids, size_t count);

size_t cpu_index(struct cpu *c);
struct cpu *cpu_find_index(size_t index);
bool cpu_on(struct cpu *c);
void cpu_off(struct cpu *c);
struct cpu *cpu_find(cpu_id_t id);
uint8_t *cpu_get_buffer(struct cpu *c);
uint32_t cpu_get_buffer_size(struct cpu *c);

#endif
