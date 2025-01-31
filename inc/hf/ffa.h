/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mpool.h"
#include "hf/vcpu.h"

void plat_ffa_log_init(void);
void plat_ffa_set_tee_enabled(bool tee_enabled);
void plat_ffa_init(struct mpool *ppool);

bool plat_ffa_is_spmd_lp_id(ffa_id_t vm_id);

void plat_save_ns_simd_context(struct vcpu *vcpu);

bool plat_ffa_handle_framework_msg(struct ffa_value args,
				   struct ffa_value *ret);
