/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa_memory_handle.h"

ffa_memory_handle_t ffa_memory_handle_make(uint64_t index)
{
#if SECURE_WORLD == 1
	return (index & ~FFA_MEMORY_HANDLE_ALLOCATOR_MASK) |
	       FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;
#else
	return index | FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
#endif
}

bool ffa_memory_handle_allocated_by_current_world(ffa_memory_handle_t handle)
{
	return (handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
#if SECURE_WORLD == 1
	       FFA_MEMORY_HANDLE_ALLOCATOR_SPMC;
#else
	       FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
#endif
}
