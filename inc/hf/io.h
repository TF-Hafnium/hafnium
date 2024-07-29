/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hf/arch/barriers.h"
#include "hf/arch/types.h"

#include "hf/assert.h"

/* Opaque types for different sized fields of memory mapped IO. */

typedef struct {
	volatile uint8_t *ptr;
} io8_t;

typedef struct {
	volatile uint16_t *ptr;
} io16_t;

typedef struct {
	volatile uint32_t *ptr;
} io32_t;

typedef struct {
	volatile uint64_t *ptr;
} io64_t;

typedef struct {
	volatile uint8_t *base;
	size_t count;
} io8_array_t;

typedef struct {
	volatile uint16_t *base;
	size_t count;
} io16_array_t;

typedef struct {
	volatile uint32_t *base;
	size_t count;
} io32_array_t;

typedef struct {
	volatile uint64_t *base;
	size_t count;
} io64_array_t;

/* Contructors for literals. */

static inline io8_t io8_c(uintpaddr_t addr, uintpaddr_t offset)
{
	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io8_t){.ptr = (volatile uint8_t *)(addr + offset)};
}

static inline io8_array_t io8_array_c(uintpaddr_t addr, uintpaddr_t offset,
				      uint32_t count)
{
	(void)offset;

	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io8_array_t){.base = (volatile uint8_t *)addr, .count = count};
}

static inline io16_t io16_c(uintpaddr_t addr, uintpaddr_t offset)
{
	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io16_t){.ptr = (volatile uint16_t *)(addr + offset)};
}

static inline io16_array_t io16_array_c(uintpaddr_t addr, uintpaddr_t offset,
					uint32_t count)
{
	(void)offset;

	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io16_array_t){.base = (volatile uint16_t *)addr,
			      .count = count};
}

static inline io32_t io32_c(uintpaddr_t addr, uintpaddr_t offset)
{
	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io32_t){.ptr = (volatile uint32_t *)(addr + offset)};
}

static inline io32_array_t io32_array_c(uintpaddr_t addr, uintpaddr_t offset,
					uint32_t count)
{
	(void)offset;

	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io32_array_t){.base = (volatile uint32_t *)addr,
			      .count = count};
}

static inline io64_t io64_c(uintpaddr_t addr, uintpaddr_t offset)
{
	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io64_t){.ptr = (volatile uint64_t *)(addr + offset)};
}

static inline io64_array_t io64_array_c(uintpaddr_t addr, uintpaddr_t offset,
					uint32_t count)
{
	(void)offset;

	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (io64_array_t){.base = (volatile uint64_t *)addr,
			      .count = count};
}

#define IO8_C(addr) io8_c((addr), 0)
#define IO16_C(addr) io16_c((addr), 0)
#define IO32_C(addr) io32_c((addr), 0)
#define IO64_C(addr) io64_c((addr), 0)

#define IO8_ARRAY_C(addr, cnt) io8_array_c((addr), 0, cnt)
#define IO16_ARRAY_C(addr, cnt) io16_array_c((addr), 0, cnt)
#define IO32_ARRAY_C(addr, cnt) io32_array_c((addr), 0, cnt)
#define IO64_ARRAY_C(addr, cnt) io64_array_c((addr), 0, cnt)

/** Read from memory-mapped IO. */

static inline uint8_t io_read8(io8_t io)
{
	return *io.ptr;
}

static inline uint16_t io_read16(io16_t io)
{
	return *io.ptr;
}

static inline uint32_t io_read32(io32_t io)
{
	return *io.ptr;
}

static inline uint64_t io_read64(io64_t io)
{
	return *io.ptr;
}

static inline uint8_t io_read8_array(io8_array_t io, size_t n)
{
	assert(n < io.count);
	return io.base[n];
}

static inline uint16_t io_read16_array(io16_array_t io, size_t n)
{
	assert(n < io.count);
	return io.base[n];
}

static inline uint32_t io_read32_array(io32_array_t io, size_t n)
{
	assert(n < io.count);
	return io.base[n];
}

static inline uint64_t io_read64_array(io64_array_t io, size_t n)
{
	assert(n < io.count);
	return io.base[n];
}

/**
 * Read from memory-mapped IO with memory barrier.
 *
 * The read is ordered before subsequent memory accesses.
 */

static inline uint8_t io_read8_mb(io8_t io)
{
	uint8_t v = io_read8(io);

	data_sync_barrier();
	return v;
}

static inline uint16_t io_read16_mb(io16_t io)
{
	uint16_t v = io_read16(io);

	data_sync_barrier();
	return v;
}

static inline uint32_t io_read32_mb(io32_t io)
{
	uint32_t v = io_read32(io);

	data_sync_barrier();
	return v;
}

static inline uint64_t io_read64_mb(io64_t io)
{
	uint64_t v = io_read64(io);

	data_sync_barrier();
	return v;
}

static inline uint8_t io_read8_array_mb(io8_array_t io, size_t n)
{
	uint8_t v = io_read8_array(io, n);

	data_sync_barrier();
	return v;
}

static inline uint16_t io_read16_array_mb(io16_array_t io, size_t n)
{
	uint16_t v = io_read16_array(io, n);

	data_sync_barrier();
	return v;
}

static inline uint32_t io_read32_array_mb(io32_array_t io, size_t n)
{
	uint32_t v = io_read32_array(io, n);

	data_sync_barrier();
	return v;
}

static inline uint64_t io_read64_array_mb(io64_array_t io, size_t n)
{
	uint64_t v = io_read64_array(io, n);

	data_sync_barrier();
	return v;
}

/* Write to memory-mapped IO. */

static inline void io_write8(io8_t io, uint8_t v)
{
	*io.ptr = v;
}

static inline void io_write16(io16_t io, uint16_t v)
{
	*io.ptr = v;
}

static inline void io_write32(io32_t io, uint32_t v)
{
	*io.ptr = v;
}

static inline void io_write64(io64_t io, uint64_t v)
{
	*io.ptr = v;
}

static inline void io_clrbits32(io32_t io, uint32_t clear)
{
	io_write32(io, io_read32(io) & ~clear);
}

static inline void io_setbits32(io32_t io, uint32_t set)
{
	io_write32(io, io_read32(io) | set);
}

static inline void io_clrsetbits32(io32_t io, uint32_t clear, uint32_t set)
{
	io_write32(io, (io_read32(io) & ~clear) | set);
}

static inline void io_write8_array(io8_array_t io, size_t n, uint8_t v)
{
	assert(n < io.count);
	io.base[n] = v;
}

static inline void io_write16_array(io16_array_t io, size_t n, uint16_t v)
{
	assert(n < io.count);
	io.base[n] = v;
}

static inline void io_write32_array(io32_array_t io, size_t n, uint32_t v)
{
	assert(n < io.count);
	io.base[n] = v;
}

static inline void io_write64_array(io64_array_t io, size_t n, uint64_t v)
{
	assert(n < io.count);
	io.base[n] = v;
}

/*
 * Write to memory-mapped IO with memory barrier.
 *
 * The write is ordered after previous memory accesses.
 */

static inline void io_write8_mb(io8_t io, uint8_t v)
{
	data_sync_barrier();
	io_write8(io, v);
}

static inline void io_write16_mb(io16_t io, uint16_t v)
{
	data_sync_barrier();
	io_write16(io, v);
}

static inline void io_write32_mb(io32_t io, uint32_t v)
{
	data_sync_barrier();
	io_write32(io, v);
}

static inline void io_write64_mb(io64_t io, uint64_t v)
{
	data_sync_barrier();
	io_write64(io, v);
}

static inline void io_write8_array_mb(io8_array_t io, size_t n, uint8_t v)
{
	data_sync_barrier();
	io_write8_array(io, n, v);
}

static inline void io_write16_array_mb(io16_array_t io, size_t n, uint16_t v)
{
	data_sync_barrier();
	io_write16_array(io, n, v);
}

static inline void io_write32_array_mb(io32_array_t io, size_t n, uint32_t v)
{
	data_sync_barrier();
	io_write32_array(io, n, v);
}

static inline void io_write64_array_mb(io64_array_t io, size_t n, uint64_t v)
{
	data_sync_barrier();
	io_write64_array(io, n, v);
}
