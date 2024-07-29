/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/std.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

typedef size_t rsize_t;

/**
 * Restrict the maximum range for range checked functions so as to be more
 * likely to catch errors. This may need to be relaxed if it proves to be overly
 * restrictive.
 */
#define RSIZE_MAX ((size_t)(128 * 1024 * 1024))

/*
 * Only the safer versions of these functions are exposed to reduce the chance
 * of misusing the versions without bounds checking or null pointer checks.
 *
 * These functions don't return errno_t as per the specification and implicitly
 * have a constraint handler that panics.
 */
/* NOLINTNEXTLINE(readability-redundant-declaration) */
void memset_s(void *dest, rsize_t destsz, int ch, rsize_t count);
/* NOLINTNEXTLINE(readability-redundant-declaration) */
void memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count);
/* NOLINTNEXTLINE(readability-redundant-declaration) */
void memmove_s(void *dest, rsize_t destsz, const void *src, rsize_t count);

/* NOLINTNEXTLINE(readability-redundant-declaration) */
void *memchr(const void *ptr, int ch, size_t count);

/* NOLINTNEXTLINE(readability-redundant-declaration) */
size_t strnlen_s(const char *str, size_t strsz);
