/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

void memcpy_trapped_aborted(void);
bool memcpy_trapped(void *dest, uint64_t dest_size, const void *src,
		    uint64_t src_size);
void memcpy_trapped_read(void);
void memcpy_trapped_write(void);
