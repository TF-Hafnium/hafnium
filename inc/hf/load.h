/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hf/boot_params.h"
#include "hf/cpio.h"
#include "hf/manifest.h"
#include "hf/memiter.h"
#include "hf/mm.h"
#include "hf/mpool.h"

bool load_vms(struct mm_stage1_locked stage1_locked,
	      const struct manifest *manifest, const struct memiter *cpio,
	      const struct boot_params *params,
	      struct boot_params_update *update, struct mpool *ppool);
