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
