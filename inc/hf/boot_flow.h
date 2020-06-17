/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/boot_params.h"
#include "hf/manifest.h"
#include "hf/memiter.h"
#include "hf/mm.h"

bool boot_flow_get_params(struct boot_params *p, const struct fdt *fdt);

bool boot_flow_update(struct mm_stage1_locked stage1_locked,
		      const struct manifest *manifest,
		      struct boot_params_update *p, struct memiter *cpio,
		      struct mpool *ppool);
