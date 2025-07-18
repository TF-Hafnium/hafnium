/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/init.h"

#include <stddef.h>

#include "hf/api.h"
#include "hf/boot_flow.h"
#include "hf/boot_params.h"
#include "hf/cpio.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/fdt_handler.h"
#include "hf/ffa.h"
#include "hf/ffa/init.h"
#include "hf/load.h"
#include "hf/manifest.h"
#include "hf/mm.h"
#include "hf/panic.h"
#include "hf/plat/boot_flow.h"
#include "hf/plat/console.h"
#include "hf/plat/interrupts.h"
#include "hf/plat/iommu.h"
#include "hf/plat/memory_alloc.h"
#include "hf/std.h"

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

	ffa_init_log();

	memory_alloc_init();

	if (!mm_init()) {
		panic("mm_init failed");
	}
}

/**
 * Performs one-time initialisation of the hypervisor.
 */
void one_time_init(void)
{
	struct string manifest_fname = STRING_INIT("manifest.dtb");
	struct fdt fdt;
	enum manifest_return_code manifest_ret;
	struct boot_params *params;
	struct boot_params_update update;
	struct memiter cpio;
	struct memiter manifest_it;
	void *initrd;
	size_t i;
	struct mm_stage1_locked mm_stage1_locked;
	struct manifest *manifest;

	arch_one_time_init();

	/* Enable locks now that mm is initialised. */
	dlog_enable_lock();
	mpool_enable_locks();

	mm_stage1_locked = mm_lock_stage1();

	if (!fdt_map(&fdt, mm_stage1_locked, plat_boot_flow_get_fdt_addr())) {
		panic("Unable to map FDT.");
	}

	params = memory_alloc(sizeof(struct boot_params));

	if (params == NULL) {
		panic("Could not use the memory allocator to allocate boot "
		      "params.");
	}

	if (!boot_flow_get_params(params, &fdt)) {
		panic("Could not parse boot params.");
	}

	for (i = 0; i < params->mem_ranges_count; ++i) {
		dlog_info("Memory range:  %#lx - %#lx\n",
			  pa_addr(params->mem_ranges[i].begin),
			  pa_addr(params->mem_ranges[i].end) - 1);
	}

	/*
	 * Hafnium manifest is either gathered from the ramdisk or passed
	 * directly to Hafnium entry point by the earlier bootloader stage.
	 * If the ramdisk start address is non-zero it hints the manifest
	 * shall be looked up from the ramdisk. If zero, assume the address
	 * passed to Hafnium entry point is the manifest address.
	 */
	if (pa_addr(params->initrd_begin)) {
		dlog_info("Ramdisk range: %#lx - %#lx\n",
			  pa_addr(params->initrd_begin),
			  pa_addr(params->initrd_end) - 1);

		/* Map initrd in, and initialise cpio parser. */
		initrd = mm_identity_map(mm_stage1_locked, params->initrd_begin,
					 params->initrd_end, MM_MODE_R);
		if (!initrd) {
			panic("Unable to map initrd.");
		}

		memiter_init(&cpio, initrd,
			     pa_difference(params->initrd_begin,
					   params->initrd_end));

		if (!cpio_get_file(&cpio, &manifest_fname, &manifest_it)) {
			panic("Could not find manifest in initrd.");
		}
	} else {
		manifest_it = fdt.buf;
	}

	dlog_verbose("Manifest range: %p - %p (%ld bytes)\n",
		     (void *)manifest_it.next, (void *)manifest_it.limit,
		     manifest_it.limit - manifest_it.next);
	if (!is_aligned(manifest_it.next, 4)) {
		panic("Manifest not aligned.");
	}

	manifest_ret = manifest_init(mm_stage1_locked, &manifest, &manifest_it,
				     params);

	if (manifest_ret != MANIFEST_SUCCESS) {
		panic("Could not parse manifest: %s.",
		      manifest_strerror(manifest_ret));
	}

	ffa_init_set_tee_enabled(manifest->ffa_tee_enabled);
	ffa_init_version();

	if (!plat_iommu_init(&fdt, mm_stage1_locked)) {
		panic("Could not initialize IOMMUs.");
	}

	cpu_module_init(params->cpu_ids, params->cpu_count);

	if (!plat_interrupts_controller_driver_init(&fdt, mm_stage1_locked)) {
		panic("Could not initialize Interrupt Controller driver.");
	}

	if (!fdt_unmap(&fdt, mm_stage1_locked)) {
		panic("Unable to unmap FDT.");
	}

	/* Load all VMs. */
	update.reserved_ranges_count = 0;

	if (!load_vms(mm_stage1_locked, manifest, &cpio, params, &update)) {
		panic("Unable to load VMs.");
	}

	if (!boot_flow_update(mm_stage1_locked, manifest, &update, &cpio)) {
		panic("Unable to update boot flow.");
	}

	/* Free space allocated for the boot parameters. */
	memory_free(params, sizeof(*params));

	mm_unlock_stage1(&mm_stage1_locked);

	/* Enable TLB invalidation for VM page table updates. */
	mm_vm_enable_invalidation();

	/* Perform platform specfic FF-A initialization. */
	ffa_init();

	/* Initialise the API page pool. ppool will be empty from now on. */
	api_init();

	dlog_info("Hafnium initialisation completed\n");
}
