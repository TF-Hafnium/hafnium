/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/ffa.h"

/**
 * Called after an SMC has been forwarded. `args` contains the arguments passed
 * to the SMC and `ret` contains the return values that will be set in the vCPU
 * registers after this call returns.
 */
void plat_smc_post_forward(struct ffa_value args, struct ffa_value *ret);
