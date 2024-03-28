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
	base8 = 8,
	base10 = 10,
	base16 = 16,
};

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
	static const char *digits_lower = "0123456789abcdefx";
	static const char *digits_upper = "0123456789ABCDEFX";
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

			fmt++;
			fmt = parse_flags(fmt, &flags);
			fmt = parse_min_width(fmt, args, &flags, &min_width);

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
				int v = va_arg(args, int);
				fmt++;

				if (v < 0) {
					flags.neg = true;
					v = -v;
				}

				chars_written += print_int((size_t)v, base10,
							   min_width, flags);
				break;
			}

			case 'X':
				fmt++;
				flags.upper = true;
				chars_written +=
					print_int(va_arg(args, size_t), base16,
						  min_width, flags);
				break;

			case 'p':
				fmt++;
				min_width = sizeof(size_t) * 2 + 2;
				flags.zero = true;
				flags.alt = true;

				chars_written +=
					print_int(va_arg(args, uintptr_t),
						  base16, min_width, flags);
				break;

			case 'x':
				fmt++;
				chars_written +=
					print_int(va_arg(args, size_t), base16,
						  min_width, flags);
				break;

			case 'u':
				fmt++;
				chars_written +=
					print_int(va_arg(args, size_t), base10,
						  min_width, flags);
				break;

			case 'o':
				fmt++;
				chars_written +=
					print_int(va_arg(args, size_t), base8,
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
