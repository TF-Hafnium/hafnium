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

#include "hf/ffa.h"

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

void dlog_enable_lock(void);
__attribute__((format(printf, 1, 2))) size_t dlog(const char *fmt, ...);
size_t vdlog(const char *fmt, va_list args);

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
