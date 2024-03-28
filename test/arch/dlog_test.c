/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"

#include <limits.h>
#include <stddef.h>

#include "hf/ffa.h"

#include "test/hftest.h"

#define assert_format(expected, ...) \
	assert_format_impl(expected, sizeof(expected), __VA_ARGS__)

static void assert_format_impl(char* expected, size_t expected_len,
			       const char* fmt, ...)
{
	va_list args;
	size_t chars_written;

	memset_s(dlog_buffer, DLOG_BUFFER_SIZE, 0, DLOG_BUFFER_SIZE);
	dlog_buffer_offset = 0;

	va_start(args, fmt);
	chars_written = vdlog(fmt, args);
	va_end(args);

	ASSERT_NE(chars_written, (size_t)-1);
	ASSERT_EQ(chars_written, expected_len - 1);

	dlog_buffer[chars_written] = '\0';
	ASSERT_STRING_EQ(expected, dlog_buffer);
	for (size_t i = expected_len - 1; i < DLOG_BUFFER_SIZE; ++i) {
		EXPECT_EQ(dlog_buffer[i], '\0');
	}
}

/**
 * Test formatting of a format string with no format specifiers
 */
TEST(dlog, no_format_specifiers)
{
	assert_format("Hello world\n", "Hello world\n");
}

/**
 * Test formatting of a format string with a percent format specifier (`%%`)
 */
TEST(dlog, percent_format_specifier)
{
	assert_format("Hello %\n", "Hello %%\n");
}

/**
 * Test formatting of a format string with a char format specifier (`%c`)
 */
TEST(dlog, char_format_specifier)
{
	assert_format("Hello w\n", "Hello %c\n", 'w');
}

/**
 * Test formatting of a format string with a string format specifier (`%s`)
 */
TEST(dlog, string_format_specifier)
{
	assert_format("Hello world\n", "Hello %s\n", "world");
}

/**
 * Test formatting of a format string with a `int` format specifier (`%d`/`%i`)
 */
TEST(dlog, int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %i\n", 0);
	assert_format("Hello 0\n", "Hello %d\n", 0);
	assert_format("Hello 1234\n", "Hello %d\n", 1234);

	assert_format("Hello 2147483647\n", "Hello %d\n", INT_MAX);
	assert_format("Hello -2147483648\n", "Hello %d\n", INT_MIN);

	assert_format("Hello -1\n", "Hello %d\n", UINT_MAX);

	assert_format("Hello -2147483648\n", "Hello %d\n",
		      ((int64_t)INT_MAX) + 1);
	assert_format("Hello 2147483647\n", "Hello %d\n",
		      ((int64_t)INT_MIN) - 1);
}

/**
 * Test formatting of a format string with a `unsigned int` format specifier
 * (`%u`)
 */
TEST(dlog, unsigned_int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %u\n", 0);
	assert_format("Hello 1234567890\n", "Hello %u\n", 1234567890);

	assert_format("Hello 4294967295\n", "Hello %u\n", UINT_MAX);
	assert_format("Hello 4294967296\n", "Hello %u\n",
		      ((uint64_t)UINT_MAX) + 1);

	assert_format("Hello 2147483648\n", "Hello %u\n", INT_MIN);
}

/**
 * Test formatting of a format string with an octal `unsigned int` format
 * specifier (`%o`)
 */
TEST(dlog, octal_unsigned_int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %o\n", 0);
	assert_format("Hello 12345670\n", "Hello %o\n", 012345670);

	assert_format("Hello 37777777777\n", "Hello %o\n", UINT_MAX);
	assert_format("Hello 40000000000\n", "Hello %o\n",
		      ((uint64_t)UINT_MAX) + 1);

	assert_format("Hello 20000000000\n", "Hello %o\n", INT_MIN);
}

/**
 * Test formatting of a format string with a hexadecimal `unsigned int` format
 * specifier (`%x`)
 */
TEST(dlog, hexadecimal_unsigned_int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %x\n", 0);
	assert_format("Hello 12345678\n", "Hello %x\n", 0x12345678);
	assert_format("Hello 9abcdef\n", "Hello %x\n", 0x9abcdef);

	assert_format("Hello 0x0\n", "Hello %#x\n", 0);
	assert_format("Hello 0x12345678\n", "Hello %#x\n", 0x12345678);
	assert_format("Hello 0x9abcdef\n", "Hello %#x\n", 0x9abcdef);

	assert_format("Hello 0X0\n", "Hello %#X\n", 0);
	assert_format("Hello 0X12345678\n", "Hello %#X\n", 0x12345678);
	assert_format("Hello 0X9ABCDEF\n", "Hello %#X\n", 0x9abcdef);
}

/**
 * Test formatting of a format string with a `void*` format
 * specifier (`%p`)
 */
TEST(dlog, pointer_format_specifier)
{
	assert_format("Hello 0x0000000000000000\n", "Hello %p\n", 0);
	assert_format("Hello 0x123456789abcdef0\n", "Hello %p\n",
		      0x123456789abcdef0);
}
