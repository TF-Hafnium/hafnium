/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/boot_params.h"
#include "hf/fdt.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/string.h"

struct fdt_header *fdt_map(struct mm_stage1_locked stage1_locked,
			   paddr_t fdt_addr, struct fdt_node *n,
			   struct mpool *ppool);
bool fdt_unmap(struct mm_stage1_locked stage1_locked, struct fdt_header *fdt,
	       struct mpool *ppool);
bool fdt_find_cpus(const struct fdt_node *root, cpu_id_t *cpu_ids,
		   size_t *cpu_count);
bool fdt_find_memory_ranges(const struct fdt_node *root,
			    struct string *device_type,
			    struct mem_range *mem_ranges,
			    size_t *mem_ranges_count, size_t mem_range_limit);
bool fdt_find_initrd(const struct fdt_node *root, paddr_t *begin, paddr_t *end);

/** Apply an update to the FDT. */
bool fdt_patch(struct mm_stage1_locked stage1_locked, paddr_t fdt_addr,
	       struct boot_params_update *p, struct mpool *ppool);
