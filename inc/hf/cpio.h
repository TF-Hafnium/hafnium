/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>

#include "hf/memiter.h"
#include "hf/string.h"

bool cpio_get_file(const struct memiter *cpio, const struct string *name,
		   struct memiter *it);
