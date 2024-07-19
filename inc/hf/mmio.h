/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "hf/io.h"

static inline uint32_t mmio_read32(void *addr)
{
	return io_read32(IO32_C((uintpaddr_t)addr));
}

static inline uint32_t mmio_read32_offset(void *addr, uint32_t offset)
{
	return io_read32(io32_c((uintpaddr_t)addr, offset));
}

static inline uint64_t mmio_read64(void *addr)
{
	return io_read64(IO64_C((uintpaddr_t)addr));
}

static inline uint64_t mmio_read64_offset(void *addr, uint32_t offset)
{
	return io_read64(io64_c((uintpaddr_t)addr, offset));
}

static inline void mmio_write32(void *addr, uint32_t data)
{
	io_write32(IO32_C((uintpaddr_t)addr), data);
}

static inline void mmio_write32_offset(void *addr, uint32_t offset,
				       uint32_t data)
{
	io_write32(io32_c((uintpaddr_t)addr, offset), data);
}

static inline void mmio_write64(void *addr, uint64_t data)
{
	io_write64(IO64_C((uintpaddr_t)addr), data);
}

static inline void mmio_write64_offset(void *addr, uint32_t offset,
				       uint64_t data)
{
	io_write64(io64_c((uintpaddr_t)addr, offset), data);
}
