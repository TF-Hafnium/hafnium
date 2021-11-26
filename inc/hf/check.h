/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/panic.h"

/**
 * Only use to check assumptions which, if false, mean the system is in a bad
 * state and it is unsafe to continue.
 *
 * Do not use if the condition could ever be legitimately false e.g. when
 * processing external inputs.
 */
#define CHECK(x)                                                          \
	do {                                                              \
		if (!(x)) {                                               \
			panic("check failed (%s) at %s:%d", #x, __FILE__, \
			      __LINE__);                                  \
		}                                                         \
	} while (0)
