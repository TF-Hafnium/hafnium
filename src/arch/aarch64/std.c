/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/std.h"

void *memset(void *s, int c, size_t n)
{
	char *p = (char *)s;

	while (n--) {
		*p++ = c;
	}

	return s;
}

void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
	char *x = dst;
	const char *y = src;

	while (n--) {
		*x = *y;
		x++;
		y++;
	}

	return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
	char *x;
	const char *y;

	if (dst < src) {
		/*
		 * Clang analyzer doesn't like us calling unsafe memory
		 * functions, so make it ignore this while still knowing that
		 * the function returns.
		 */
#ifdef __clang_analyzer__
		return dst;
#else
		return memcpy(dst, src, n);
#endif
	}

	x = (char *)dst + n - 1;
	y = (const char *)src + n - 1;

	while (n--) {
		*x = *y;
		x--;
		y--;
	}

	return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
	const char *x = a;
	const char *y = b;

	while (n--) {
		if (*x != *y) {
			return *x - *y;
		}
		x++;
		y++;
	}

	return 0;
}

int strncmp(const char *a, const char *b, size_t n)
{
	char x = 0;
	char y = 0;

	while (n > 0) {
		x = *a++;
		y = *b++;
		if (x == 0 || x != y) {
			break;
		}
		--n;
	}

	return x - y;
}
