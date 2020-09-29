/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdarg.h>
#include <stddef.h>

#include "hf/spci.h"

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

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define dlog_error(...) dlog("ERROR: " __VA_ARGS__)
#else
#define dlog_error(...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_NOTICE
#define dlog_notice(...) dlog("NOTICE: " __VA_ARGS__)
#else
#define dlog_notice(...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARNING
#define dlog_warning(...) dlog("WARNING: " __VA_ARGS__)
#else
#define dlog_warning(...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define dlog_info(...) dlog("INFO: " __VA_ARGS__)
#else
#define dlog_info(...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_VERBOSE
#define dlog_verbose(...) dlog("VERBOSE: " __VA_ARGS__)
#else
#define dlog_verbose(...)
#endif

void dlog_flush_vm_buffer(spci_vm_id_t id, char buffer[], size_t length);
