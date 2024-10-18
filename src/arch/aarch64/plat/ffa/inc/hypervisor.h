/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>

bool plat_ffa_is_tee_enabled(void);

void plat_ffa_set_tee_enabled(bool tee_enabled);
