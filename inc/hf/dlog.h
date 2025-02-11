/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdarg.h>
#include <stddef.h>

#define DLOG_BUFFER_SIZE 8192

enum log_level {
	LOG_LEVEL_NONE = 0,
	LOG_LEVEL_ERROR = 1,
	LOG_LEVEL_NOTICE = 2,
	LOG_LEVEL_WARNING = 3,
	LOG_LEVEL_INFO = 4,
	LOG_LEVEL_VERBOSE = 5,
};

extern size_t dlog_buffer_offset;
extern char dlog_buffer[];

/**
 * This struct is a workaround to allow passing `va_list` by pointer on x86_64.
 * On x86_64, `va_list` is an array, and in C arrays are weird.
 *
 * In particular, function parameters of array types are really pointers: the
 * functions `void f(char[1])` and `void f(char*)` are identical (see
 * https://en.cppreference.com/w/c/language/array). But this does not apply to
 * function parameters of type pointer to array: the functions `void
 * f(char(*)[1])` and `void f(char**)` are not identical.
 *
 * Therefore in the body of `by_value`, `args` has type `__va_list_tag *`.
 * The call to `by_pointer` will cause a compile error, as `&args` has type
 * `va_list_tag **` but `by_pointer` expects `va_list (*)[1]`.
 *
 * ```
 * typedef va_list __va_list_tag[1];
 *
 * void by_pointer(va_list *args) {}
 *
 * void by_value(va_list args) {
 *    by_pointer(&args);
 * }
 * ```
 *
 * The workaround to prevent array to pointer decay is to wrap the array in a
 * struct, since structs do not decay to pointers.
 */
struct va_list_wrapper {
	va_list va;
};

void dlog_enable_lock(void);
__attribute__((format(printf, 1, 2))) size_t dlog(const char *fmt, ...);
size_t vdlog(const char *fmt, struct va_list_wrapper *args);

/*
 * The do { ... } while (0) syntax is used to ensure that callers of
 * these macros follow them with a semicolon.
 *
 * Run-time conditionals are preferred over preprocessor conditionals to ensure
 * that the code is type-checked and linted unconditionally, even if it will not
 * be executed at run-time.  Logging statements that are disabled at
 * compile-time are unreachable code and will be eliminated by compiler
 * optimizations.
 */
#define dlog_error(...)                              \
	do {                                         \
		if (LOG_LEVEL >= LOG_LEVEL_ERROR) {  \
			dlog("ERROR: " __VA_ARGS__); \
		}                                    \
	} while (0)

#define dlog_notice(...)                              \
	do {                                          \
		if (LOG_LEVEL >= LOG_LEVEL_NOTICE) {  \
			dlog("NOTICE: " __VA_ARGS__); \
		}                                     \
	} while (0)

#define dlog_warning(...)                              \
	do {                                           \
		if (LOG_LEVEL >= LOG_LEVEL_WARNING) {  \
			dlog("WARNING: " __VA_ARGS__); \
		}                                      \
	} while (0)

#define dlog_info(...)                                \
	do {                                          \
		if (LOG_LEVEL >= LOG_LEVEL_WARNING) { \
			dlog("INFO: " __VA_ARGS__);   \
		}                                     \
	} while (0)

#define dlog_verbose(...)                              \
	do {                                           \
		if (LOG_LEVEL >= LOG_LEVEL_VERBOSE) {  \
			dlog("VERBOSE: " __VA_ARGS__); \
		}                                      \
	} while (0)

/** Print to debug log, with `indent` amount of indentation. */
#define dlog_indent(indent, ...)               \
	do {                                   \
		dlog("%*s", (indent) * 2, ""); \
		dlog(__VA_ARGS__);             \
	} while (0)
