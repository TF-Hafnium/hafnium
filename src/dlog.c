/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"

#include <stdbool.h>
#include <stddef.h>

#include "hf/spinlock.h"
#include "hf/static_assert.h"
#include "hf/std.h"
#include "hf/stdout.h"

enum { DLOG_MAX_STRING_LENGTH = 64 };

/* Keep fields aligned */
/* clang-format off */
struct format_flags {
	bool minus	: 1;
	bool plus	: 1;
	bool space	: 1;
	bool alt	: 1;
	bool zero	: 1;
	bool upper	: 1;
	bool neg	: 1;
};
/* clang-format on */

enum format_base {
	base2 = 2,
	base8 = 8,
	base10 = 10,
	base16 = 16,
};

enum format_length {
	length8 = 8,
	length16 = 16,
	length32 = 32,
	length64 = 64,
};

static_assert(sizeof(char) == sizeof(uint8_t),
	      "dlog expects char to be 8 bits wide");
static_assert(sizeof(short) == sizeof(uint16_t),
	      "dlog expects short to be 16 bits wide");
static_assert(sizeof(int) == sizeof(uint32_t),
	      "dlog expects int to be 32 bits wide");
static_assert(sizeof(long) == sizeof(uint64_t),
	      "dlog expects long to be 64 bits wide");
static_assert(sizeof(long long) == sizeof(uint64_t),
	      "dlog expects long long to be 64 bits wide");
static_assert(sizeof(intmax_t) == sizeof(uint64_t),
	      "dlog expects intmax_t to be 64 bits wide");
static_assert(sizeof(size_t) == sizeof(uint64_t),
	      "dlog expects size_t to be 64 bits wide");
static_assert(sizeof(ptrdiff_t) == sizeof(uint64_t),
	      "dlog expects ptrdiff_t to be 64 bits wide");

static bool dlog_lock_enabled = false;
static struct spinlock sl = SPINLOCK_INIT;

/*
 * These global variables for the log buffer are not static because a test needs
 * to access them directly.
 */
size_t dlog_buffer_offset;
char dlog_buffer[DLOG_BUFFER_SIZE];

/**
 * Takes the lock, if it is enabled.
 */
static void lock(void)
{
	if (dlog_lock_enabled) {
		sl_lock(&sl);
	}
}

/**
 * Releases the lock, if it is enabled.
 */
static void unlock(void)
{
	if (dlog_lock_enabled) {
		sl_unlock(&sl);
	}
}

/**
 * Enables the lock protecting the serial device.
 */
void dlog_enable_lock(void)
{
	dlog_lock_enabled = true;
}

static void dlog_putchar(char c)
{
	dlog_buffer[dlog_buffer_offset] = c;
	dlog_buffer_offset = (dlog_buffer_offset + 1) % DLOG_BUFFER_SIZE;
	stdout_putchar(c);
}

/**
 * Prints a literal string (i.e. '%' is not interpreted specially) to the debug
 * log.
 *
 * Returns number of characters written.
 */
static size_t print_raw_string(const char *str)
{
	const char *c = str;

	for (; *c != '\0'; c++) {
		dlog_putchar(*c);
	}

	return c - str;
}

/**
 * Prints a formatted string to the debug log. The format includes a minimum
 * width, the fill character, and flags (whether to align to left or right).
 *
 * str is the full string, while suffix is a pointer within str that indicates
 * where the suffix begins. This is used when printing right-aligned numbers
 * with a zero fill; for example, -10 with width 4 should be padded to -010,
 * so suffix would point to index one of the "-10" string .
 *
 * Returns number of characters written.
 */
static size_t print_string(const char *str, const char *suffix,
			   size_t min_width, struct format_flags flags,
			   char fill)
{
	size_t chars_written = 0;
	size_t len = suffix - str;

	/* Print the string up to the beginning of the suffix. */
	while (str != suffix) {
		chars_written++;
		dlog_putchar(*str++);
	}

	if (flags.minus) {
		/* Left-aligned. Print suffix, then print padding if needed. */
		len += print_raw_string(suffix);
		while (len < min_width) {
			chars_written++;
			dlog_putchar(' ');
			len++;
		}
		return chars_written;
	}

	/* Fill until we reach the desired length. */
	len += strnlen_s(suffix, DLOG_MAX_STRING_LENGTH);
	while (len < min_width) {
		chars_written++;
		dlog_putchar(fill);
		len++;
	}

	/* Now print the rest of the string. */
	chars_written += print_raw_string(suffix);
	return chars_written;
}

/**
 * Prints an integer to the debug log. The caller specifies the base, its
 * minimum width and printf-style flags.
 *
 * Returns number of characters written.
 */
static size_t print_int(size_t value, enum format_base base, size_t min_width,
			struct format_flags flags)
{
	static const char *digits_lower = "0123456789abcdefxb";
	static const char *digits_upper = "0123456789ABCDEFXB";
	const char *digits = flags.upper ? digits_upper : digits_lower;
	char buf[DLOG_MAX_STRING_LENGTH];
	char *ptr = &buf[sizeof(buf) - 1];
	char *num;
	*ptr = '\0';
	do {
		--ptr;
		*ptr = digits[value % base];
		value /= base;
	} while (value);

	/* Num stores where the actual number begins. */
	num = ptr;

	/* Add prefix if requested. */
	if (flags.alt) {
		switch (base) {
		case base16:
			ptr -= 2;
			ptr[0] = '0';
			ptr[1] = digits[16];
			break;

		case base2:
			ptr -= 2;
			ptr[0] = '0';
			ptr[1] = digits[17];
			break;

		case base8:
			ptr--;
			*ptr = '0';
			break;

		case base10:
			/* do nothing */
			break;
		}
	}

	/* Add sign if requested. */
	if (flags.neg) {
		*--ptr = '-';
	} else if (flags.plus) {
		*--ptr = '+';
	} else if (flags.space) {
		*--ptr = ' ';
	}
	return print_string(ptr, num, min_width, flags, flags.zero ? '0' : ' ');
}

/**
 * Parses the optional flags field of a printf-style format. Returns a pointer
 * to the first non-flag character in the string.
 */
static const char *parse_flags(const char *fmt, struct format_flags *flags)
{
	for (;; fmt++) {
		switch (*fmt) {
		case '-':
			flags->minus = true;
			break;

		case '+':
			flags->plus = true;
			break;

		case ' ':
			flags->space = true;
			break;

		case '#':
			flags->alt = true;
			break;

		case '0':
			flags->zero = true;
			break;

		default:
			return fmt;
		}
	}
}

/**
 * Parses the optional length modifier field of a printf-style format.
 *
 * Returns a pointer to the first non-length modifier character in the string.
 */
static const char *parse_length_modifier(const char *fmt,
					 enum format_length *length)
{
	switch (*fmt) {
	case 'h':
		fmt++;
		if (*fmt == 'h') {
			fmt++;
			*length = length8;
		} else {
			*length = length16;
		}
		break;
	case 'l':
		fmt++;
		if (*fmt == 'l') {
			fmt++;
			*length = length64;
		} else {
			*length = length64;
		}
		break;

	case 'j':
	case 'z':
	case 't':
		fmt++;
		*length = length64;
		break;

	default:
		*length = length32;
		break;
	}

	return fmt;
}

/**
 * Parses the optional minimum width field of a printf-style format.
 * If the width is negative, `flags.minus` is set.
 *
 * Returns a pointer to the first non-digit character in the string.
 */
static const char *parse_min_width(const char *fmt, va_list args,
				   struct format_flags *flags, int *min_width)
{
	int width = 0;

	/* Read minimum width from arguments. */
	if (*fmt == '*') {
		fmt++;
		width = va_arg(args, int);
		if (width < 0) {
			width = -width;
			flags->minus = true;
		}
	} else {
		for (; *fmt >= '0' && *fmt <= '9'; fmt++) {
			width = (width * 10) + (*fmt - '0');
		}
	}

	*min_width = width;

	return fmt;
}

/**
 * Reinterpret an unsigned 64-bit integer as a potentially shorter unsigned
 * integer according to the length modifier.
 * Returns an unsigned integer suitable for passing to `print_int`.
 */
uint64_t reinterpret_unsigned_int(enum format_length length, uint64_t value)
{
	switch (length) {
	case length8:
		return (uint8_t)value;
	case length16:
		return (uint16_t)value;
	case length32:
		return (uint32_t)value;
	case length64:
		return value;
	}
}

/**
 * Reinterpret an unsigned 64-bit integer as a potentially shorter signed
 * integer according to the length modifier.
 *
 * Returns an *unsigned* integer suitable for passing to `print_int`. If the
 * reinterpreted value is negative, `flags.neg` is set and the absolute value is
 * returned.
 */
uint64_t reinterpret_signed_int(enum format_length length, uint64_t value,
				struct format_flags *flags)
{
	int64_t signed_value = (int64_t)reinterpret_unsigned_int(length, value);

	switch (length) {
	case length8:
		if ((int8_t)signed_value < 0) {
			flags->neg = true;
			signed_value = (-signed_value) & 0xFF;
		}
		break;
	case length16:
		if ((int16_t)signed_value < 0) {
			flags->neg = true;
			signed_value = (-signed_value) & 0xFFFF;
		}
		break;
	case length32:
		if ((int32_t)signed_value < 0) {
			flags->neg = true;
			signed_value = (-signed_value) & 0xFFFFFFFF;
		}
		break;
	case length64:
		if (signed_value < 0) {
			flags->neg = true;
			signed_value = -signed_value;
		}
		break;
	}

	return signed_value;
}

/**
 * Same as "dlog", except that arguments are passed as a va_list
 *
 * Returns number of characters written, or `-1` if format string is invalid.
 */
size_t vdlog(const char *fmt, va_list args)
{
	size_t chars_written = 0;

	lock();

	while (*fmt != '\0') {
		switch (*fmt) {
		default:
			chars_written++;
			dlog_putchar(*fmt);
			fmt++;
			break;

		case '%': {
			struct format_flags flags = {0};
			int min_width = 0;
			enum format_length length = length32;
			uint64_t value;

			fmt++;
			fmt = parse_flags(fmt, &flags);
			fmt = parse_min_width(fmt, args, &flags, &min_width);
			fmt = parse_length_modifier(fmt, &length);

			/* Handle the format specifier. */
			switch (*fmt) {
			case '%':
				fmt++;
				chars_written++;
				dlog_putchar('%');
				break;

			case 'c': {
				char str[2] = {va_arg(args, int), 0};

				fmt++;
				chars_written += print_string(
					str, str, min_width, flags, ' ');
				break;
			}

			case 's': {
				char *str = va_arg(args, char *);

				fmt++;
				chars_written += print_string(
					str, str, min_width, flags, ' ');
				break;
			}

			case 'd':
			case 'i': {
				fmt++;
				value = va_arg(args, uint64_t);
				value = reinterpret_signed_int(length, value,
							       &flags);

				chars_written += print_int(value, base10,
							   min_width, flags);
				break;
			}

			case 'b':
				fmt++;
				value = va_arg(args, uint64_t);
				value = reinterpret_unsigned_int(length, value);

				chars_written += print_int(value, base2,
							   min_width, flags);
				break;

			case 'B':
				fmt++;
				flags.upper = true;
				value = va_arg(args, uint64_t);
				value = reinterpret_unsigned_int(length, value);

				chars_written += print_int(value, base2,
							   min_width, flags);
				break;

			case 'o':
				fmt++;
				value = va_arg(args, uint64_t);
				value = reinterpret_unsigned_int(length, value);

				chars_written += print_int(value, base8,
							   min_width, flags);
				break;

			case 'x':
				fmt++;
				value = va_arg(args, uint64_t);
				value = reinterpret_unsigned_int(length, value);

				chars_written += print_int(value, base16,
							   min_width, flags);
				break;

			case 'X':
				fmt++;
				flags.upper = true;
				value = va_arg(args, uint64_t);
				value = reinterpret_unsigned_int(length, value);

				chars_written += print_int(value, base16,
							   min_width, flags);
				break;

			case 'u':
				fmt++;
				value = va_arg(args, uint64_t);
				value = reinterpret_unsigned_int(length, value);

				chars_written += print_int(value, base10,
							   min_width, flags);
				break;

			case 'p':
				fmt++;
				value = va_arg(args, uint64_t);
				min_width = sizeof(size_t) * 2 + 2;
				flags.zero = true;
				flags.alt = true;

				chars_written += print_int(value, base16,
							   min_width, flags);
				break;

			default:
				chars_written = -1;
				goto out;
			}
		}
		}
	}

out:
	stdout_flush();
	unlock();
	return chars_written;
}

/**
 * Prints the given format string to the debug log.
 *
 * The format string supported is the same as described in
 * https://en.cppreference.com/w/c/io/fprintf, with the following exceptions:
 * - Floating-point formatters (`%f`, `%F`, `%e`, `%E`, `%a`, `%A`, `%g`, `%G`,
 *   `%L`) are not supported because floats are not used in Hafnium and
 *   formatting them is too complicated.
 * - `%n` is not supported because it is rarely used and potentially dangerous.
 * - Precision modifiers (`%.*` and `%.` followed by an integer) are not
 *   supported.
 *
 * Returns number of characters written, or `-1` if format string is invalid.
 */
size_t dlog(const char *fmt, ...)
{
	size_t chars_written = 0;
	va_list args;

	va_start(args, fmt);
	chars_written = vdlog(fmt, args);
	va_end(args);
	return chars_written;
}
