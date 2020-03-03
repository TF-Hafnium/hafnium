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

#include "hf/arch/init.h"

#include <stdalign.h>
#include <stddef.h>

#include "hf/api.h"
#include "hf/boot_flow.h"
#include "hf/boot_params.h"
#include "hf/cpio.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/fdt_handler.h"
#include "hf/load.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/panic.h"
#include "hf/plat/boot_flow.h"
#include "hf/plat/console.h"
#include "hf/plat/iommu.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"

alignas(alignof(
	struct mm_page_table)) char ptable_buf[sizeof(struct mm_page_table) *
					       HEAP_PAGES];

static struct mpool ppool;

/**
 * Performs one-time initialisation of memory management for the hypervisor.
 *
 * This is the only C code entry point called with MMU and caching disabled. The
 * page table returned is used to set up the MMU and caches for all subsequent
 * code.
 */
void one_time_init_mm(void)
{
	/* Make sure the console is initialised before calling dlog. */
	plat_console_init();

	dlog_notice("Initialising hafnium\n");

	mpool_init(&ppool, sizeof(struct mm_page_table));
	mpool_add_chunk(&ppool, ptable_buf, sizeof(ptable_buf));

	if (!mm_init(&ppool)) {
		panic("mm_init failed");
	}
}

/**
 * Performs one-time initialisation of the hypervisor.
 */
void one_time_init(void)
{
	struct string manifest_fname = STRING_INIT("manifest.dtb");
	struct fdt_header *fdt;
	struct fdt_node fdt_root;
	struct manifest manifest;
	enum manifest_return_code manifest_ret;
	struct boot_params params;
	struct boot_params_update update;
	struct memiter cpio;
	struct memiter manifest_it;
	void *initrd;
	size_t i;
	struct mm_stage1_locked mm_stage1_locked;

	arch_one_time_init();

	/* Enable locks now that mm is initialised. */
	dlog_enable_lock();
	mpool_enable_locks();

	mm_stage1_locked = mm_lock_stage1();

	fdt = fdt_map(mm_stage1_locked, plat_boot_flow_get_fdt_addr(),
		      &fdt_root, &ppool);
	if (fdt == NULL) {
		panic("Unable to map FDT.");
	}

	if (!fdt_find_child(&fdt_root, "")) {
		panic("Unable to find FDT root node.");
	}

	if (!boot_flow_get_params(&params, &fdt_root)) {
		panic("Could not parse boot params.");
	}

	for (i = 0; i < params.mem_ranges_count; ++i) {
		dlog_info("Memory range:  %#x - %#x\n",
			  pa_addr(params.mem_ranges[i].begin),
			  pa_addr(params.mem_ranges[i].end) - 1);
	}

	dlog_info("Ramdisk range: %#x - %#x\n", pa_addr(params.initrd_begin),
		  pa_addr(params.initrd_end) - 1);

	/* Map initrd in, and initialise cpio parser. */
	initrd = mm_identity_map(mm_stage1_locked, params.initrd_begin,
				 params.initrd_end, MM_MODE_R, &ppool);
	if (!initrd) {
		panic("Unable to map initrd.");
	}

	memiter_init(&cpio, initrd,
		     pa_difference(params.initrd_begin, params.initrd_end));

	if (!cpio_get_file(&cpio, &manifest_fname, &manifest_it)) {
		panic("Could not find manifest in initrd.");
	}

	dlog_verbose("Manifest range: %#x - %#x (%d bytes)\n", manifest_it.next,
		     manifest_it.limit, manifest_it.limit - manifest_it.next);
	if (!is_aligned(manifest_it.next, 4)) {
		panic("Manifest not aligned.");
	}

	manifest_ret = manifest_init(&manifest, &manifest_it);
	if (manifest_ret != MANIFEST_SUCCESS) {
		panic("Could not parse manifest: %s.",
		      manifest_strerror(manifest_ret));
	}

	if (!plat_iommu_init(&fdt_root, mm_stage1_locked, &ppool)) {
		panic("Could not initialize IOMMUs.");
	}

	if (!fdt_unmap(mm_stage1_locked, fdt, &ppool)) {
		panic("Unable to unmap FDT.");
	}

	cpu_module_init(params.cpu_ids, params.cpu_count);

	/* Load all VMs. */
	update.reserved_ranges_count = 0;
	if (!load_vms(mm_stage1_locked, &manifest, &cpio, &params, &update,
		      &ppool)) {
		panic("Unable to load VMs.");
	}

	if (!boot_flow_update(mm_stage1_locked, &manifest, &update, &cpio,
			      &ppool)) {
		panic("Unable to update boot flow.");
	}

	mm_defrag(mm_stage1_locked, &ppool);
	mm_unlock_stage1(&mm_stage1_locked);

	/* Initialise the API page pool. ppool will be empty from now on. */
	api_init(&ppool);

	/* Enable TLB invalidation for VM page table updates. */
	mm_vm_enable_invalidation();

	dlog_info("Hafnium initialisation completed\n");
}
