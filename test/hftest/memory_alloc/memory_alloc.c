/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdbool.h>

#include "hf/arch/std.h"

#include "hf/check.h"
#include "hf/mm.h"
#include "hf/mpool.h"

alignas(PAGE_SIZE) char memory_alloc_buf[PAGE_SIZE * HEAP_PAGES];
static struct mpool memory_alloc_pool;

void memory_alloc_init(void)
{
	mpool_init(&memory_alloc_pool, PAGE_SIZE);
	mpool_add_chunk(&memory_alloc_pool, memory_alloc_buf,
			sizeof(memory_alloc_buf));
}

void *memory_alloc(size_t size)
{
	size_t count = (align_up(size, memory_alloc_pool.entry_size) /
			memory_alloc_pool.entry_size);

	return mpool_alloc_contiguous(&memory_alloc_pool, count, 1);
}

void memory_free(void *begin, size_t size)
{
	CHECK(mpool_add_chunk(&memory_alloc_pool, begin,
			      align_up(size, memory_alloc_pool.entry_size)));
}
