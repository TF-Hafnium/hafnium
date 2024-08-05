/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hf/arch/types.h"

#include "hf/assert.h"

/** An opaque type for a physical address. */
typedef struct {
	uintpaddr_t pa;
} paddr_t;

/** An opaque type for an intermediate physical address. */
typedef struct {
	uintpaddr_t ipa;
} ipaddr_t;

/** An opaque type for a virtual address. */
typedef struct {
	uintvaddr_t va;
} vaddr_t;

/**
 * Initializes a physical address.
 */
static inline paddr_t pa_init(uintpaddr_t p)
{
	return (paddr_t){.pa = p};
}

/**
 * Extracts the absolute physical address.
 */
static inline uintpaddr_t pa_addr(paddr_t pa)
{
	return pa.pa;
}

/**
 * Advances a physical address.
 */
static inline paddr_t pa_add(paddr_t pa, size_t n)
{
	return pa_init(pa_addr(pa) + n);
}

/**
 * Move backward physical address.
 */
static inline paddr_t pa_subtract(paddr_t pa, size_t n)
{
	return pa_init(pa_addr(pa) - n);
}

/**
 * Returns the difference between two physical addresses.
 */
static inline size_t pa_difference(paddr_t start, paddr_t end)
{
	return pa_addr(end) - pa_addr(start);
}

/**
 * Initializes an intermediate physical address.
 */
static inline ipaddr_t ipa_init(uintpaddr_t ipa)
{
	return (ipaddr_t){.ipa = ipa};
}

/**
 * Subtract from a physical address.
 */
static inline paddr_t pa_sub(paddr_t pa, size_t n)
{
	assert((uintptr_t)pa_addr(pa) >= n);
	return pa_init(pa_addr(pa) - n);
}

/**
 * Extracts the absolute intermediate physical address.
 */
static inline uintpaddr_t ipa_addr(ipaddr_t ipa)
{
	return ipa.ipa;
}

/**
 * Advances an intermediate physical address.
 */
static inline ipaddr_t ipa_add(ipaddr_t ipa, size_t n)
{
	return ipa_init(ipa_addr(ipa) + n);
}

/**
 * Initializes a virtual address.
 */
static inline vaddr_t va_init(uintvaddr_t v)
{
	return (vaddr_t){.va = v};
}

/**
 * Extracts the absolute virtual address.
 */
static inline uintvaddr_t va_addr(vaddr_t va)
{
	return va.va;
}

/**
 * Casts a physical address to a virtual address.
 */
static inline vaddr_t va_from_pa(paddr_t pa)
{
	return va_init(pa_addr(pa));
}

/**
 * Casts a physical address to an intermediate physical address.
 */
static inline ipaddr_t ipa_from_pa(paddr_t pa)
{
	return ipa_init(pa_addr(pa));
}

/**
 * Casts a virtual address to a physical address.
 */
static inline paddr_t pa_from_va(vaddr_t va)
{
	return pa_init(va_addr(va));
}

/**
 * Casts an intermediate physical address to a physical address.
 */
static inline paddr_t pa_from_ipa(ipaddr_t ipa)
{
	return pa_init(ipa_addr(ipa));
}

/**
 * Casts a pointer to a virtual address.
 */
static inline vaddr_t va_from_ptr(const void *p)
{
	return (vaddr_t){.va = (uintvaddr_t)p};
}

/**
 * Casts a virtual address to a pointer. Only use when the virtual address is
 * mapped for the calling context.
 * TODO: check the mapping for a range and return a memiter?
 */
static inline void *ptr_from_va(vaddr_t va)
{
	/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
	return (void *)va_addr(va);
}

/**
 * Advances a virtual address.
 */
static inline vaddr_t va_add(vaddr_t va, size_t n)
{
	return va_init(va_addr(va) + n);
}
