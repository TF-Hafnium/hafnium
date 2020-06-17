/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "hf/check.h"

#include "vmapi/hf/ffa.h"

#define FFA_VERSION_RESERVED_BIT UINT32_C(1U << 31)

static inline struct ffa_value ffa_error(uint64_t error_code)
{
	return (struct ffa_value){.func = FFA_ERROR_32, .arg2 = error_code};
}

/**
 * Return the offset to the first constituent within the
 * `ffa_composite_memory_region` for the given receiver from an
 * `ffa_memory_region`. The caller must check that the receiver_index is within
 * bounds, and that it has a composite memory region offset.
 */
static inline uint32_t ffa_composite_constituent_offset(
	struct ffa_memory_region *memory_region, uint32_t receiver_index)
{
	CHECK(receiver_index < memory_region->receiver_count);
	CHECK(memory_region->receivers[receiver_index]
		      .composite_memory_region_offset != 0);

	return memory_region->receivers[receiver_index]
		       .composite_memory_region_offset +
	       sizeof(struct ffa_composite_memory_region);
}
