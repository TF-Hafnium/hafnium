/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

void memory_alloc_init(void);
void *memory_alloc(size_t size);
bool memory_free(void *begin, size_t size);

bool memory_alloc_rollback_init(void);
bool memory_alloc_rollback_fini(void);
