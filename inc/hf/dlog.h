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

#define LOG_LEVEL_NONE UINT32_C(0)
#define LOG_LEVEL_ERROR UINT32_C(1)
#define LOG_LEVEL_NOTICE UINT32_C(2)
#define LOG_LEVEL_WARNING UINT32_C(3)
#define LOG_LEVEL_INFO UINT32_C(4)
#define LOG_LEVEL_VERBOSE UINT32_C(5)

extern size_t dlog_buffer_offset;
extern char dlog_buffer[];

void dlog_enable_lock(void);
void dlog(const char *fmt, ...);
void vdlog(const char *fmt, va_list args);

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

void dlog_flush_vm_buffer(ffa_id_t id, char buffer[], size_t length);
