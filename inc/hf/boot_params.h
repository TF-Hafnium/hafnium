/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>

#include "hf/arch/cpu.h"

#include "hf/fdt.h"
#include "hf/mm.h"
#include "hf/mpool.h"

#define MAX_MEM_RANGES 20
#define MAX_DEVICE_MEM_RANGES 10

struct mem_range {
	paddr_t begin;
	paddr_t end;
};

struct boot_params {
	cpu_id_t cpu_ids[MAX_CPUS];
	size_t cpu_count;
	struct mem_range mem_ranges[MAX_MEM_RANGES];
	size_t mem_ranges_count;
	struct mem_range ns_mem_ranges[MAX_MEM_RANGES];
	size_t ns_mem_ranges_count;
	struct mem_range device_mem_ranges[MAX_DEVICE_MEM_RANGES];
	size_t device_mem_ranges_count;
	struct mem_range ns_device_mem_ranges[MAX_DEVICE_MEM_RANGES];
	size_t ns_device_mem_ranges_count;

	paddr_t initrd_begin;
	paddr_t initrd_end;
	uintreg_t kernel_arg;
};

struct boot_params_update {
	struct mem_range reserved_ranges[MAX_MEM_RANGES];
	size_t reserved_ranges_count;
	paddr_t initrd_begin;
	paddr_t initrd_end;
};
