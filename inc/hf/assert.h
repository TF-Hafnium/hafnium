/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#if !defined(__cplusplus)

#include <stdint.h>

#include "hf/dlog.h"
#include "hf/panic.h"

#ifndef PLAT_LOG_LEVEL_ASSERT
#define PLAT_LOG_LEVEL_ASSERT LOG_LEVEL
#endif

#define assert(e) assert_impl(e, __FILE__, __LINE__, #e)

static inline void assert_impl(bool cond, const char *file, uint32_t line,
			       const char *expr)
{
	if (!ENABLE_ASSERTIONS) {
		return;
	}

	if (cond) {
		return;
	}

	if (PLAT_LOG_LEVEL_ASSERT >= LOG_LEVEL_VERBOSE) {
		panic("ASSERT: %s:%d:%s\n", file, line, expr);
	} else if (PLAT_LOG_LEVEL_ASSERT >= LOG_LEVEL_INFO) {
		panic("ASSERT: %s:%d\n", file, line);
	} else {
		panic("ASSERT\n");
	}
}

#else
#include <assert.h>
#endif /* !defined(__cplusplus) */
