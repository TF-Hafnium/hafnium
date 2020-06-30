/*
 * Copyright 2018 The Hafnium Authors.
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

#define FDT_PROP_INITRD_START "linux,initrd-start"
#define FDT_PROP_INITRD_END "linux,initrd-end"

bool fdt_struct_from_ptr(const void *fdt_ptr, struct fdt *fdt);
bool fdt_map(struct fdt *fdt, struct mm_stage1_locked stage1_locked,
	     paddr_t fdt_addr, struct mpool *ppool);
bool fdt_unmap(struct fdt *fdt, struct mm_stage1_locked stage1_locked,
	       struct mpool *ppool);
bool fdt_find_cpus(const struct fdt *fdt, cpu_id_t *cpu_ids, size_t *cpu_count);
bool fdt_find_memory_ranges(const struct fdt *fdt,
			    const struct string *device_type,
			    struct mem_range *mem_ranges,
			    size_t *mem_ranges_count, size_t mem_range_limit);
bool fdt_find_initrd(const struct fdt *fdt, paddr_t *begin, paddr_t *end);
bool fdt_get_memory_size(const struct fdt *fdt, size_t *size);
