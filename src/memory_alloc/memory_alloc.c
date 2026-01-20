/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/std.h"
#include "hf/arch/vcpu.h"

#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/mm.h"
#include "hf/mpool.h"

alignas(PAGE_SIZE) char memory_alloc_buf[PAGE_SIZE * HEAP_PAGES];
static struct mpool memory_alloc_pool;

void memory_alloc_init(void)
{
	static bool memory_initialized = false;

	assert(!memory_initialized);

	if (!memory_initialized) {
		mpool_init(&memory_alloc_pool, PAGE_SIZE);
		mpool_add_chunk(&memory_alloc_pool, memory_alloc_buf,
				sizeof(memory_alloc_buf));
		memory_initialized = true;
	}
}

void *memory_alloc(size_t size)
{
	size_t count = align_up(size, memory_alloc_pool.entry_size) /
		       memory_alloc_pool.entry_size;
	void *entry;
	struct cpu *current_cpu = arch_current_cpu();

	/*
	 * Allocate from the rollback memory of the currently running cpu. If
	 * it is not configured (i.e., If rollback mechanism is not available
	 * yet), just use the base memory pool.
	 */
	entry = cpu_rollback_memory_alloc(current_cpu, count);

	return (entry != NULL) ? entry
			       : mpool_alloc_contiguous(&memory_alloc_pool,
							count, count);
}

bool memory_free(void *begin, size_t size)
{
	struct cpu *current_cpu = arch_current_cpu();

	size = align_up(size, memory_alloc_pool.entry_size);

	/*
	 * In case the roolback memory is configured from the current CPU, free
	 * to the CPU's local pool of memory.
	 */
	if (cpu_rollback_memory_free(current_cpu, begin, size)) {
		return true;
	}

	/* Else, free to the global memory pool. */
	return mpool_add_chunk(&memory_alloc_pool, begin, size);
}

/**
 * Some operations may require a safe fallback. E.g. memory management
 * operations, which require the available heap pages to be preserved so they
 * can't be starved of memory while doing a memory allocation operation.
 * Returns true if successfully initialised the rollback mechanism.
 */
bool memory_alloc_rollback_init(void)
{
	struct cpu *current_cpu = arch_current_cpu();

	/*
	 * Get the current cpu structure, and prepare its roolback
	 * memory pool.
	 */
	return cpu_rollback_memory_init(current_cpu, &memory_alloc_pool);
}

bool memory_alloc_rollback_fini(void)
{
	struct cpu *current_cpu = arch_current_cpu();

	return cpu_rollback_memory_fini(current_cpu);
}
