/*
 * Copyright 2019 The Hafnium Authors.
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
	struct string device_memory = STRING_INIT("device-memory");

	p->mem_ranges_count = 0;
	p->kernel_arg = plat_boot_flow_get_kernel_arg();

	return plat_boot_flow_get_initrd_range(fdt, &p->initrd_begin,
					       &p->initrd_end) &&
	       fdt_find_cpus(fdt, p->cpu_ids, &p->cpu_count) &&
	       fdt_find_memory_ranges(fdt, &memory, p->mem_ranges,
				      &p->mem_ranges_count, MAX_MEM_RANGES) &&
	       fdt_find_memory_ranges(fdt, &device_memory, p->device_mem_ranges,
				      &p->device_mem_ranges_count,
				      MAX_DEVICE_MEM_RANGES);
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
