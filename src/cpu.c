/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"

#include <stdalign.h>

#include "hf/arch/cache.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "system/sys/cdefs.h"

/**
 * The stacks to be used by the CPUs.
 *
 * Defined in assembly for aarch64 in "src/arch/aarch64/stacks.S."
 * Defined for host-based unit tests in "src/cpu_test.cc".
 */

extern char callstacks[MAX_CPUS][STACK_SIZE];

/* NOLINTNEXTLINE(misc-redundant-expression) */
static_assert((STACK_SIZE % PAGE_SIZE) == 0, "Keep each stack page aligned.");
static_assert((PAGE_SIZE % STACK_ALIGN) == 0,
	      "Page alignment is too weak for the stack.");

/**
 * Internal buffer used to store FF-A messages from a VM Tx. Its usage prevents
 * TOCTOU issues while Hafnium performs actions on information that would
 * otherwise be re-writable by the VM.
 *
 * Each buffer is owned by a single CPU. Can be used when handling FF-A memory
 * management ABIs, and FF-A Indirect Messaging.
 */
alignas(PAGE_SIZE) static uint8_t cpu_message_buffer[MAX_CPUS][PAGE_SIZE];

uint8_t *cpu_get_buffer(struct cpu *c)
{
	size_t cpu_indx = cpu_index(c);

	CHECK(cpu_indx < MAX_CPUS);

	return cpu_message_buffer[cpu_indx];
}

uint32_t cpu_get_buffer_size(struct cpu *c)
{
	size_t cpu_indx = cpu_index(c);

	CHECK(cpu_indx < MAX_CPUS);

	return sizeof(cpu_message_buffer[cpu_indx]);
}

/* State of all supported CPUs. The stack of the first one is initialized. */
struct cpu cpus[MAX_CPUS] = {
	{
		.is_on = 1,
		.stack_bottom = &callstacks[0][STACK_SIZE],
	},
};

uint32_t cpu_count = 1;

void cpu_module_init(const cpu_id_t *cpu_ids, size_t count)
{
	uint32_t i;
	uint32_t j;
	cpu_id_t boot_cpu_id = cpus[0].id;
	bool found_boot_cpu = false;

	cpu_count = count;

	/*
	 * Initialize CPUs with the IDs from the configuration passed in. The
	 * CPUs after the boot CPU are initialized in reverse order. The boot
	 * CPU is initialized when it is found or in place of the last CPU if it
	 * is not found.
	 */
	j = cpu_count;
	for (i = 0; i < cpu_count; ++i) {
		struct cpu *c;
		struct timer_pending_vcpu_list *timer_list;
		cpu_id_t id = cpu_ids[i];

		if (found_boot_cpu || id != boot_cpu_id) {
			--j;
			c = &cpus[j];
			c->stack_bottom = &callstacks[j][STACK_SIZE];
		} else {
			found_boot_cpu = true;
			c = &cpus[0];
			CHECK(c->stack_bottom == &callstacks[0][STACK_SIZE]);
		}

		sl_init(&c->lock);
		c->id = id;

		timer_list = &c->pending_timer_vcpus_list;

		/*
		 * Initialize the list of vCPUs with pending arch timer for
		 * each CPU. The root entry fields is configured such that
		 * its `prev` and `next` fields point to itself.
		 */
		list_init(&(timer_list->root_entry));
	}

	if (!found_boot_cpu) {
		/* Boot CPU was initialized but with wrong ID. */
		dlog_warning("Boot CPU's ID not found in config.\n");
		cpus[0].id = boot_cpu_id;
	}

	/*
	 * Clean the cache for the cpus array such that secondary cores
	 * hitting the entry point can read the cpus array consistently
	 * with MMU off (hence data cache off).
	 */
	arch_cache_data_clean_range(va_from_ptr(cpus), sizeof(cpus));

	arch_cache_data_clean_range(va_from_ptr(&cpu_count), sizeof(cpu_count));
}

size_t cpu_index(struct cpu *c)
{
	return c - cpus;
}

/*
 * Return cpu with the given index.
 */
struct cpu *cpu_find_index(size_t index)
{
	return (index < MAX_CPUS) ? &cpus[index] : NULL;
}

/**
 * Turns CPU on and returns the previous state.
 */
bool cpu_on(struct cpu *c)
{
	bool prev;

	sl_lock(&c->lock);
	prev = c->is_on;
	c->is_on = true;
	sl_unlock(&c->lock);

	return prev;
}

/**
 * Prepares the CPU for turning itself off.
 */
void cpu_off(struct cpu *c)
{
	sl_lock(&c->lock);
	c->is_on = false;
	sl_unlock(&c->lock);
}

/**
 * Searches for a CPU based on its ID.
 */
struct cpu *cpu_find(cpu_id_t id)
{
	size_t i;

	for (i = 0; i < cpu_count; i++) {
		if (cpus[i].id == id) {
			return &cpus[i];
		}
	}

	return NULL;
}
