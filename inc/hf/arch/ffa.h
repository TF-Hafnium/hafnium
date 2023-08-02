/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"

/** Returns information on features that are specific to the arch */
struct ffa_value arch_ffa_features(uint32_t function_id);

/** Returns the SPMC ID. */
ffa_id_t arch_ffa_spmc_id_get(void);

/** Called once at boot time to initialize the platform ffa module. */
void arch_ffa_init(void);
