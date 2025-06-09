/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/std.h"

void memory_alloc_init(void);
void *memory_alloc(size_t size);
void memory_free(void *begin, size_t size);

/* Temporary function to help with code refactor. */
struct mpool *memory_alloc_get_ppool(void);
