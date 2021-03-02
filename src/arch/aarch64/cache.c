/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/cache.h"

#include "hf/arch/barriers.h"

#include "hf/addr.h"

#include "msr.h"

/**
 * Return the cache line size for the cache level at the point of coherency.
 */
static size_t arch_cache_line_size_get(void)
{
	uint64_t level_of_coherency;
	uint64_t line_size;

	/* Get the level of coherence for the cache hierarchy. */
	level_of_coherency = read_msr(clidr_el1);
	level_of_coherency = (level_of_coherency >> 24) & 3;

	/* Select required level of cache. */
	write_msr(csselr_el1, (level_of_coherency - 1) << 1);

	/* Get line size such that cache_line_size = 2^(line_size + 4). */
	line_size = read_msr(ccsidr_el1) & 3;

	return (1 << (line_size + 4));
}

/**
 * Clean the cache to the point of coherency for the range qualified by the
 * start address and size arguments.
 */
void arch_cache_clean_range(vaddr_t start, size_t size)
{
	size_t cache_line_size = arch_cache_line_size_get();
	uintvaddr_t begin = va_addr(start);
	uintvaddr_t end = begin + size;
	uintvaddr_t address;

	for (address = begin; address < end; address += cache_line_size) {
		/* Cache clean by VA to PoC */
		__asm__ volatile("dc cvac, %0" : : "r"(address));
	}

	memory_ordering_barrier();
}
