/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "hf/spinlock.h"

struct mpool {
	struct spinlock lock;
	size_t entry_size;
	struct mpool_chunk *chunk_list;
	struct mpool_entry *entry_list;
	struct mpool *fallback;
};

void mpool_enable_locks(void);
void mpool_init(struct mpool *p, size_t entry_size);
void mpool_init_from(struct mpool *p, struct mpool *from);
void mpool_init_with_fallback(struct mpool *p, struct mpool *fallback);
void mpool_fini(struct mpool *p);
bool mpool_add_chunk(struct mpool *p, void *begin, size_t size);
void *mpool_alloc(struct mpool *p);
void *mpool_alloc_contiguous(struct mpool *p, size_t count, size_t align);
void mpool_free(struct mpool *p, void *ptr);
