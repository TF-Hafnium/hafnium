/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/cache.h"

void arch_cache_data_clean_range(vaddr_t start, size_t size)
{
	(void)start;
	(void)size;
}

void arch_cache_data_invalidate_range(vaddr_t start, size_t size)
{
	(void)start;
	(void)size;
}
