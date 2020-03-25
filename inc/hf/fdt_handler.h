/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "hf/boot_params.h"
#include "hf/fdt.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/string.h"

#define FDT_PROP_INITRD_START "linux,initrd-start"
#define FDT_PROP_INITRD_END "linux,initrd-end"

bool fdt_map(struct fdt *fdt, struct mm_stage1_locked stage1_locked,
	     paddr_t fdt_addr, struct mpool *ppool);
bool fdt_unmap(struct fdt *fdt, struct mm_stage1_locked stage1_locked,
	       struct mpool *ppool);
bool fdt_find_cpus(const struct fdt *fdt, cpu_id_t *cpu_ids, size_t *cpu_count);
bool fdt_find_memory_ranges(const struct fdt *fdt, struct string *device_type,
			    struct mem_range *mem_ranges,
			    size_t *mem_ranges_count, size_t mem_range_limit);
bool fdt_find_initrd(const struct fdt *fdt, paddr_t *begin, paddr_t *end);
