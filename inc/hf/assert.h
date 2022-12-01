/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#if !defined(__cplusplus)

#include "hf/panic.h"

#ifndef PLAT_LOG_LEVEL_ASSERT
#define PLAT_LOG_LEVEL_ASSERT LOG_LEVEL
#endif

#if ENABLE_ASSERTIONS
#if PLAT_LOG_LEVEL_ASSERT >= LOG_LEVEL_VERBOSE
#define assert(e) \
	((e) ? (void)0 : panic("ASSERT: %s:%d:%s\n", __FILE__, __LINE__, #e))
#elif PLAT_LOG_LEVEL_ASSERT >= LOG_LEVEL_INFO
#define assert(e) ((e) ? (void)0 : panic("ASSERT: %s:%d\n", __FILE__, __LINE__))
#else
#define assert(e) ((e) ? (void)0 : panic("ASSERT\n"))
#endif
#else
#define assert(e) ((void)0)
#endif /* ENABLE_ASSERTIONS */

#else
#include <assert.h>
#endif /* !defined(__cplusplus) */
