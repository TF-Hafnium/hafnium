/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/boot_flow.h"
#include "hf/dlog.h"
#include "hf/fdt_handler.h"
#include "hf/plat/boot_flow.h"

/**
 * Extract the boot parameters from the FDT and the boot-flow driver.
 */
bool boot_flow_get_params(struct boot_params *p, const struct fdt *fdt)
{
	struct string memory = STRING_INIT("memory");
	struct string ns_memory = STRING_INIT("ns-memory");
	struct string device_memory = STRING_INIT("device-memory");
	struct string ns_device_memory = STRING_INIT("ns-device-memory");

	p->mem_ranges_count = 0;
	p->kernel_arg = plat_boot_flow_get_kernel_arg();

	return plat_boot_flow_get_initrd_range(fdt, &p->initrd_begin,
					       &p->initrd_end) &&
	       fdt_find_cpus(fdt, p->cpu_ids, &p->cpu_count) &&
	       fdt_find_memory_ranges(fdt, &memory, p->mem_ranges,
				      &p->mem_ranges_count, MAX_MEM_RANGES) &&
	       fdt_find_memory_ranges(fdt, &ns_memory, p->ns_mem_ranges,
				      &p->ns_mem_ranges_count,
				      MAX_MEM_RANGES) &&
	       fdt_find_memory_ranges(fdt, &device_memory, p->device_mem_ranges,
				      &p->device_mem_ranges_count,
				      MAX_DEVICE_MEM_RANGES) &&
	       fdt_find_memory_ranges(
		       fdt, &ns_device_memory, p->ns_device_mem_ranges,
		       &p->ns_device_mem_ranges_count, MAX_DEVICE_MEM_RANGES);
}

/**
 * Takes action on any updates that were generated.
 */
bool boot_flow_update(struct mm_stage1_locked stage1_locked,
		      const struct manifest *manifest,
		      struct boot_params_update *p, struct memiter *cpio,
		      struct mpool *ppool)
{
	return plat_boot_flow_update(stage1_locked, manifest, p, cpio, ppool);
}
