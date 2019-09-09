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

#include "hf/boot_params.h"

#include "hf/dlog.h"
#include "hf/fdt_handler.h"
#include "hf/layout.h"
#include "hf/manifest.h"
#include "hf/plat/boot_flow.h"

/**
 * Extract the boot parameters from the FDT and the boot-flow driver.
 */
bool boot_params_init(struct boot_params *p, const struct fdt_node *fdt_root)
{
	p->mem_ranges_count = 0;
	p->kernel_arg = plat_get_kernel_arg();

	return plat_get_initrd_range(fdt_root, &p->initrd_begin,
				     &p->initrd_end) &&
	       fdt_find_cpus(fdt_root, p->cpu_ids, &p->cpu_count) &&
	       fdt_find_memory_ranges(fdt_root, p);
}

/**
 * Updates the FDT before being passed to the primary VM's kernel.
 *
 * TODO: in future, each VM will declare whether it expects an argument passed
 * and that will be static data e.g. it will provide its own FDT so there will
 * be no FDT modification. This is done because each VM has a very different
 * view of the system and we don't want to force VMs to require loader code when
 * another loader can load the data for it.
 */
bool boot_params_patch_fdt(struct mm_stage1_locked stage1_locked,
			   struct boot_params_update *p, struct mpool *ppool)
{
	return fdt_patch(stage1_locked, plat_get_fdt_addr(), p, ppool);
}
