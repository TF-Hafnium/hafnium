/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/std.h"

#include "hf/check.h"
#include "hf/panic.h"

/* Declare unsafe functions locally so they are not available globally. */
void *memset(void *s, int c, size_t n);
void *memcpy(void *restrict dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);

void memset_s(void *dest, rsize_t destsz, int ch, rsize_t count)
{
	if (dest == NULL || destsz > RSIZE_MAX) {
		panic("memset_s failed as either dest == NULL "
		      "or destsz > RSIZE_MAX.\n");
	}

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memset(dest, ch, (count <= destsz ? count : destsz));
}

/* Check the preconditions for memcpy and panic if they are not upheld. */
void memcpy_check_preconditions(void *dest, rsize_t destsz, const void *src,
				rsize_t count, size_t alignment)
{
	uintptr_t d = (uintptr_t)dest;
	uintptr_t s = (uintptr_t)src;

	if (dest == NULL) {
		panic("memcpy: dest == NULL\n");
	}
	if (src == NULL) {
		panic("memcpy: src == NULL\n");
	}

	/* Check count <= destsz <= RSIZE_MAX. */
	if (destsz > RSIZE_MAX) {
		panic("memcpy: destsz > RSIZE_MAX (%u > %u)\n", destsz,
		      RSIZE_MAX);
	}
	if (count > destsz) {
		panic("memcpy: destsz > count (%u > %u)\n", destsz, count);
	}

	/*
	 * Buffer overlap test.
	 * case a) `d < s` implies `s >= d+count`
	 * case b) `d > s` implies `d >= s+count`
	 */
	if (d == s || !(d < s || d >= (s + count)) ||
	    !(d > s || s >= (d + count))) {
		panic("memcpy: dest and src overlap\n");
	}

	if (!is_aligned(dest, alignment)) {
		panic("memcpy: dest not aligned (%p %% %u == %u)\n", dest,
		      alignment, d % alignment);
	}
	if (!is_aligned(src, alignment)) {
		panic("memcpy: src not aligned (%p %% %u == %u)\n", src,
		      alignment, s % alignment);
	}
}

void memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
	memcpy_check_preconditions(dest, destsz, src, count, 1);

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memcpy(dest, src, count);
}

void memmove_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
	if (dest == NULL) {
		panic("memove: dest == NULL\n");
	}
	if (src == NULL) {
		panic("memove: src == NULL\n");
	}

	/* Check count <= destsz <= RSIZE_MAX. */
	if (destsz > RSIZE_MAX) {
		panic("memmove: destsz > RSIZE_MAX (%u > %u)\n", destsz,
		      RSIZE_MAX);
	}
	if (count > destsz) {
		panic("memmove: count > destsz (%u > %u)\n", count, destsz);
	}

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memmove(dest, src, count);
}

/**
 * Finds the first occurrence of character `ch` in the first `count` bytes of
 * memory pointed to by `ptr`.
 *
 * Returns NULL if `ch` is not found.
 * Panics if `ptr` is NULL (undefined behaviour).
 */
void *memchr(const void *ptr, int ch, size_t count)
{
	size_t i;
	const unsigned char *p = (const unsigned char *)ptr;

	CHECK(ptr != NULL);

	/* Iterate over at most `strsz` characters of `str`. */
	for (i = 0; i < count; ++i) {
		if (p[i] == (unsigned char)ch) {
			return (void *)(&p[i]);
		}
	}

	return NULL;
}

/**
 * Returns the length of the null-terminated byte string `str`, examining at
 * most `strsz` bytes.
 *
 * If `str` is a NULL pointer, it returns zero.
 * If a NULL character is not found, it returns `strsz`.
 */
size_t strnlen_s(const char *str, size_t strsz)
{
	if (str == NULL) {
		return 0;
	}

	for (size_t i = 0; i < strsz; ++i) {
		if (str[i] == '\0') {
			return i;
		}
	}

	/* NULL character not found. */
	return strsz;
}
