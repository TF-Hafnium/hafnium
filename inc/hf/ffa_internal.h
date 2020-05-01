/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

#include "hf/check.h"

#include "vmapi/hf/ffa.h"

#define FFA_VERSION_MAJOR 0x1
#define FFA_VERSION_MINOR 0x0

#define FFA_VERSION_MAJOR_OFFSET 16
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
