/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/boot_params.h"
#include "hf/fdt.h"
#include "hf/manifest.h"
#include "hf/memiter.h"
#include "hf/mm.h"

paddr_t plat_boot_flow_get_fdt_addr(void);
uintreg_t plat_boot_flow_get_kernel_arg(void);
bool plat_boot_flow_get_initrd_range(const struct fdt *fdt, paddr_t *begin,
				     paddr_t *end);
bool plat_boot_flow_update(struct mm_stage1_locked stage1_locked,
			   const struct manifest *manifest,
			   struct boot_params_update *p, struct memiter *cpio,
			   struct mpool *ppool);
