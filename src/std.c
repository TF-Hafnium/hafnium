/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/std.h"

#include "hf/check.h"

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

void memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
	uintptr_t d = (uintptr_t)dest;
	uintptr_t s = (uintptr_t)src;

	CHECK(dest != NULL);
	CHECK(src != NULL);

	/* Check count <= destsz <= RSIZE_MAX. */
	CHECK(destsz <= RSIZE_MAX);
	CHECK(count <= destsz);

	/*
	 * Buffer overlap test.
	 * case a) `d < s` implies `s >= d+count`
	 * case b) `d > s` implies `d >= s+count`
	 */
	CHECK(d != s);
	CHECK(d < s || d >= (s + count));
	CHECK(d > s || s >= (d + count));

	/*
	 * Clang analyzer doesn't like us calling unsafe memory functions, so
	 * make it ignore this call.
	 */
	// NOLINTNEXTLINE
	memcpy(dest, src, count);
}

void memmove_s(void *dest, rsize_t destsz, const void *src, rsize_t count)
{
	CHECK(dest != NULL);
	CHECK(src != NULL);

	/* Check count <= destsz <= RSIZE_MAX. */
	CHECK(destsz <= RSIZE_MAX);
	CHECK(count <= destsz);

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
