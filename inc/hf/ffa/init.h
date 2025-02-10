/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mpool.h"

void ffa_init_log(void);
void ffa_init(struct mpool *ppool);

bool ffa_init_is_tee_enabled(void);
void ffa_init_set_tee_enabled(bool tee_enabled);
