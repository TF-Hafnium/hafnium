/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/boot_params.h"
#include "hf/types.h"

/**
 * Aggregates all the necessary ranges needed for Hafnium to
 * load an SP.
 */
struct partition_pkg {
	/* Memory range for the partition manifest. */
	struct mem_range pm;
	/* Memory range for the image. */
	struct mem_range img;
	/* Memory range for the HOB list. - optional, if absent set to 0. */
	struct mem_range hob;
	/* Memory range for the FF-A boot info descriptors. */
	struct mem_range boot_info;
	/* Memory range for the totality of the package. */
	struct mem_range total;
};

bool partition_pkg_init(struct mm_stage1_locked stage1_locked,
			paddr_t pkg_start, struct partition_pkg *pkg,
			struct mpool *ppool);

void partition_pkg_deinit(struct mm_stage1_locked stage1_locked,
			  struct partition_pkg *pkg, struct mpool *ppool);
