/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/mm.h"

struct mem_range {
	paddr_t begin;
	paddr_t end;
};

static inline struct mem_range make_mem_range(uintptr_t base_address,
					      uint32_t page_count)
{
	return (struct mem_range){
		.begin = pa_init(base_address),
		.end = pa_init(base_address + page_count * PAGE_SIZE - 1),
	};
}

static inline bool mem_range_contains_address(struct mem_range range,
					      uintptr_t address)
{
	return pa_addr(range.begin) <= address && address <= pa_addr(range.end);
}

static inline bool mem_range_overlaps(struct mem_range a, struct mem_range b)
{
	return mem_range_contains_address(a, pa_addr(b.begin)) ||
	       mem_range_contains_address(a, pa_addr(b.end));
}

static inline bool mem_range_contains_range(struct mem_range a,
					    struct mem_range b)
{
	return mem_range_contains_address(a, pa_addr(b.begin)) &&
	       mem_range_contains_address(a, pa_addr(b.end));
}

static inline bool mem_range_aligns(struct mem_range range, size_t alignment)
{
	return (pa_addr(range.begin) % alignment) == 0U;
}

static inline bool mem_range_is_valid(struct mem_range range)
{
	return pa_addr(range.begin) != 0U && pa_addr(range.end) != 0U;
}
