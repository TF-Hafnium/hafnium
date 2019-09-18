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
#include "hf/load.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/panic.h"
#include "hf/plat/console.h"
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

	dlog("Initialising hafnium\n");

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
	struct manifest manifest;
	struct boot_params params;
	struct boot_params_update update;
	struct memiter cpio;
	void *initrd;
	size_t i;
	struct mm_stage1_locked mm_stage1_locked;

	arch_one_time_init();

	/* Enable locks now that mm is initialised. */
	dlog_enable_lock();
	mpool_enable_locks();

	mm_stage1_locked = mm_lock_stage1();

	if (!boot_flow_init(mm_stage1_locked, &manifest, &params, &ppool)) {
		panic("Could not parse data from FDT.");
	}

	cpu_module_init(params.cpu_ids, params.cpu_count);

	for (i = 0; i < params.mem_ranges_count; ++i) {
		dlog("Memory range:  %#x - %#x\n",
		     pa_addr(params.mem_ranges[i].begin),
		     pa_addr(params.mem_ranges[i].end) - 1);
	}

	dlog("Ramdisk range: %#x - %#x\n", pa_addr(params.initrd_begin),
	     pa_addr(params.initrd_end) - 1);

	/* Map initrd in, and initialise cpio parser. */
	initrd = mm_identity_map(mm_stage1_locked, params.initrd_begin,
				 params.initrd_end, MM_MODE_R, &ppool);
	if (!initrd) {
		panic("Unable to map initrd.");
	}

	memiter_init(&cpio, initrd,
		     pa_difference(params.initrd_begin, params.initrd_end));

	/* Load all VMs. */
	update.reserved_ranges_count = 0;
	if (!load_vms(mm_stage1_locked, &manifest, &cpio, &params, &update,
		      &ppool)) {
		panic("Unable to load VMs.");
	}

	/* Prepare to run by updating bootparams as seen by primary VM. */
	if (!boot_params_patch_fdt(mm_stage1_locked, &update, &ppool)) {
		panic("plat_update_boot_params failed");
	}

	mm_defrag(mm_stage1_locked, &ppool);
	mm_unlock_stage1(&mm_stage1_locked);

	/* Initialise the API page pool. ppool will be empty from now on. */
	api_init(&ppool);

	/* Enable TLB invalidation for VM page table updates. */
	mm_vm_enable_invalidation();

	dlog("Hafnium initialisation completed\n");
}
