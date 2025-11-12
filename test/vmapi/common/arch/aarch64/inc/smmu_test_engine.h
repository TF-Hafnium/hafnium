/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <hf/std.h>

/*
 * Attribute encoding for Inner and Outer:
 * Read-Allocate Write-Allocate Write-Back Normal Memory
 */
#define ATTR_ACACHE_RAWAWB_S (0xffU)
#define ATTR_ACACHE_RAWAWB_NS (0x2ffU)

/* Source attributes occupy the bottom halfword */
#define DMA_ENGINE_ATTR_SRC_ACACHE_RAWAWB_S ATTR_ACACHE_RAWAWB_S
#define DMA_ENGINE_ATTR_SRC_ACACHE_RAWAWB_NS ATTR_ACACHE_RAWAWB_NS

/* Destination attributes occupy the top halfword */
#define DMA_ENGINE_ATTR_DEST_ACACHE_RAWAWB_S (ATTR_ACACHE_RAWAWB_S << 16)
#define DMA_ENGINE_ATTR_DEST_ACACHE_RAWAWB_NS (ATTR_ACACHE_RAWAWB_NS << 16)

bool run_smmuv3_rand48(uintptr_t start_address, size_t size,
		       uint32_t attributes);
bool run_smmuv3_memcpy(uintptr_t start_address, size_t size,
		       uint32_t attributes);
