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

/*
 * The MIN/MAX macros are bound to 64-bit variables to ensure the values are
 * passed to `dlog` as 64-bit integers. This tests that length modifiers like
 * `%hh`, `%h` and `%u` correctly read only the lower 8/16/32 bits of the value
 * passed in.
 */
const uint64_t u8_max = UINT8_MAX;
const uint64_t i8_min = INT8_MIN;
const uint64_t i8_max = INT8_MAX;

const uint64_t u16_max = UINT16_MAX;
const uint64_t i16_min = INT16_MIN;
const uint64_t i16_max = INT16_MAX;

const uint64_t u32_max = UINT32_MAX;
const uint64_t i32_min = INT32_MIN;
const uint64_t i32_max = INT32_MAX;

const uint64_t u64_max = UINT64_MAX;
const uint64_t i64_min = INT64_MIN;
const uint64_t i64_max = INT64_MAX;

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

	assert_format("Hello 2147483647\n", "Hello %d\n", i32_max);
	assert_format("Hello -2147483648\n", "Hello %d\n", i32_min);

	assert_format("Hello -1\n", "Hello %d\n", u32_max);

	assert_format("Hello -2147483648\n", "Hello %d\n", i32_max + 1);
	assert_format("Hello 2147483647\n", "Hello %d\n", i32_min - 1);
}

/**
 * Test formatting of a format string with a `unsigned int` format specifier
 * (`%u`)
 */
TEST(dlog, unsigned_int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %u\n", 0);
	assert_format("Hello 1234567890\n", "Hello %u\n", 1234567890);

	assert_format("Hello 4294967295\n", "Hello %u\n", u32_max);
	assert_format("Hello 0\n", "Hello %u\n", u32_max + 1);

	assert_format("Hello 2147483648\n", "Hello %u\n", i32_min);
}

/**
 * Test formatting of a format string with an octal `unsigned int` format
 * specifier (`%o`)
 */
TEST(dlog, octal_unsigned_int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %o\n", 0);
	assert_format("Hello 12345670\n", "Hello %o\n", 012345670);

	assert_format("Hello 37777777777\n", "Hello %o\n", u32_max);
	assert_format("Hello 0\n", "Hello %o\n", u32_max + 1);

	assert_format("Hello 20000000000\n", "Hello %o\n", i32_min);
}

/**
 * Test formatting of a format string with a binary `unsigned int` format
 * specifier (`%b`)
 */
TEST(dlog, binary_unsigned_int_format_specifier)
{
	assert_format("Hello 0\n", "Hello %b\n", 0);
	assert_format("Hello 11111111111111111111111111111111\n", "Hello %b\n",
		      u32_max);

	assert_format("Hello 0b0\n", "Hello %#b\n", 0);
	assert_format("Hello 0b11111111111111111111111111111111\n",
		      "Hello %#b\n", u32_max);

	assert_format("Hello 0B0\n", "Hello %#B\n", 0);
	assert_format("Hello 0B11111111111111111111111111111111\n",
		      "Hello %#B\n", u32_max);
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

TEST(dlog, unsigned_length_modifiers)
{
	assert_format("Hello 0\n", "Hello %hhu\n", 0);
	assert_format("Hello 255\n", "Hello %hhu\n", u8_max);
	assert_format("Hello 0\n", "Hello %hhu\n", u8_max + 1);

	assert_format("Hello 0\n", "Hello %hu\n", 0);
	assert_format("Hello 255\n", "Hello %hu\n", u8_max);
	assert_format("Hello 256\n", "Hello %hu\n", u8_max + 1);
	assert_format("Hello 65535\n", "Hello %hu\n", u16_max);
	assert_format("Hello 0\n", "Hello %hu\n", u16_max + 1);

	assert_format("Hello 0\n", "Hello %lu\n", 0);
	assert_format("Hello 255\n", "Hello %lu\n", u8_max);
	assert_format("Hello 256\n", "Hello %lu\n", u8_max + 1);
	assert_format("Hello 65535\n", "Hello %lu\n", u16_max);
	assert_format("Hello 65536\n", "Hello %lu\n", u16_max + 1);
	assert_format("Hello 4294967295\n", "Hello %lu\n", u32_max);
	assert_format("Hello 4294967296\n", "Hello %lu\n", u32_max + 1);
	assert_format("Hello 18446744073709551615\n", "Hello %lu\n", u64_max);
	assert_format("Hello 0\n", "Hello %lu\n", u64_max + 1);

	assert_format("Hello 0\n", "Hello %llu\n", 0);
	assert_format("Hello 255\n", "Hello %llu\n", u8_max);
	assert_format("Hello 256\n", "Hello %llu\n", u8_max + 1);
	assert_format("Hello 65535\n", "Hello %llu\n", u16_max);
	assert_format("Hello 65536\n", "Hello %llu\n", u16_max + 1);
	assert_format("Hello 4294967295\n", "Hello %llu\n", u32_max);
	assert_format("Hello 4294967296\n", "Hello %llu\n", u32_max + 1);
	assert_format("Hello 18446744073709551615\n", "Hello %llu\n", u64_max);
	assert_format("Hello 0\n", "Hello %llu\n", u64_max + 1);
}

TEST(dlog, signed_length_modifiers)
{
	assert_format("Hello 0\n", "Hello %hhd\n", 0);
	assert_format("Hello -1\n", "Hello %hhd\n", u8_max);
	assert_format("Hello 0\n", "Hello %hhd\n", u8_max + 1);
	assert_format("Hello 127\n", "Hello %hhd\n", i8_max);
	assert_format("Hello -128\n", "Hello %hhd\n", i8_min);

	assert_format("Hello 0\n", "Hello %hd\n", 0);
	assert_format("Hello 255\n", "Hello %hd\n", u8_max);
	assert_format("Hello 256\n", "Hello %hd\n", u8_max + 1);
	assert_format("Hello 127\n", "Hello %hd\n", i8_max);
	assert_format("Hello -128\n", "Hello %hd\n", i8_min);
	assert_format("Hello -1\n", "Hello %hd\n", u16_max);
	assert_format("Hello 0\n", "Hello %hd\n", u16_max + 1);
	assert_format("Hello 32767\n", "Hello %hd\n", i16_max);
	assert_format("Hello -32768\n", "Hello %hd\n", i16_min);

	assert_format("Hello 0\n", "Hello %ld\n", 0);
	assert_format("Hello 255\n", "Hello %ld\n", u8_max);
	assert_format("Hello 256\n", "Hello %ld\n", u8_max + 1);
	assert_format("Hello 127\n", "Hello %ld\n", i8_max);
	assert_format("Hello -128\n", "Hello %ld\n", i8_min);
	assert_format("Hello 65535\n", "Hello %ld\n", u16_max);
	assert_format("Hello 65536\n", "Hello %ld\n", u16_max + 1);
	assert_format("Hello 32767\n", "Hello %ld\n", i16_max);
	assert_format("Hello -32768\n", "Hello %ld\n", i16_min);
	assert_format("Hello 4294967295\n", "Hello %ld\n", u32_max);
	assert_format("Hello 4294967296\n", "Hello %ld\n", u32_max + 1);
	assert_format("Hello 2147483647\n", "Hello %ld\n", i32_max);
	assert_format("Hello -2147483648\n", "Hello %ld\n", i32_min);
	assert_format("Hello -1\n", "Hello %ld\n", u64_max);
	assert_format("Hello 9223372036854775807\n", "Hello %ld\n", i64_max);
	assert_format("Hello -9223372036854775808\n", "Hello %ld\n", i64_min);

	assert_format("Hello 0\n", "Hello %lld\n", 0);
	assert_format("Hello 255\n", "Hello %lld\n", u8_max);
	assert_format("Hello 256\n", "Hello %lld\n", u8_max + 1);
	assert_format("Hello 127\n", "Hello %lld\n", i8_max);
	assert_format("Hello -128\n", "Hello %lld\n", i8_min);
	assert_format("Hello 65535\n", "Hello %lld\n", u16_max);
	assert_format("Hello 65536\n", "Hello %lld\n", u16_max + 1);
	assert_format("Hello 32767\n", "Hello %lld\n", i16_max);
	assert_format("Hello -32768\n", "Hello %lld\n", i16_min);
	assert_format("Hello 4294967295\n", "Hello %lld\n", u32_max);
	assert_format("Hello 4294967296\n", "Hello %lld\n", u32_max + 1);
	assert_format("Hello 2147483647\n", "Hello %lld\n", i32_max);
	assert_format("Hello -2147483648\n", "Hello %lld\n", i32_min);
	assert_format("Hello -1\n", "Hello %lld\n", u64_max);
	assert_format("Hello 9223372036854775807\n", "Hello %lld\n", i64_max);
	assert_format("Hello -9223372036854775808\n", "Hello %lld\n", i64_min);
}
