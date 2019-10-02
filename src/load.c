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

#include "hf/load.h"

#include <stdbool.h>

#include "hf/api.h"
#include "hf/boot_params.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/layout.h"
#include "hf/memiter.h"
#include "hf/mm.h"
#include "hf/plat/console.h"
#include "hf/static_assert.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"

/**
 * Copies data to an unmapped location by mapping it for write, copying the
 * data, then unmapping it.
 *
 * The data is written so that it is available to all cores with the cache
 * disabled. When switching to the partitions, the caching is initially disabled
 * so the data must be available without the cache.
 */
static bool copy_to_unmapped(struct mm_stage1_locked stage1_locked, paddr_t to,
			     struct memiter *from_it, struct mpool *ppool)
{
	const void *from = memiter_base(from_it);
	size_t size = memiter_size(from_it);
	paddr_t to_end = pa_add(to, size);
	void *ptr;

	ptr = mm_identity_map(stage1_locked, to, to_end, MM_MODE_W, ppool);
	if (!ptr) {
		return false;
	}

	memcpy_s(ptr, size, from, size);
	arch_mm_flush_dcache(ptr, size);

	CHECK(mm_unmap(stage1_locked, to, to_end, ppool));

	return true;
}

static bool load_kernel(struct mm_stage1_locked stage1_locked, paddr_t begin,
			paddr_t end, const struct manifest_vm *manifest_vm,
			const struct memiter *cpio, struct mpool *ppool)
{
	struct memiter kernel;

	if (string_is_empty(&manifest_vm->kernel_filename)) {
		/* This signals the kernel has been preloaded. */
		return true;
	}

	if (!cpio_get_file(cpio, &manifest_vm->kernel_filename, &kernel)) {
		dlog("Could not find kernel file \"%s\".\n",
		     string_data(&manifest_vm->kernel_filename));
		return false;
	}

	if (pa_difference(begin, end) < memiter_size(&kernel)) {
		dlog("Kernel is larger than available memory.\n");
		return false;
	}

	if (!copy_to_unmapped(stage1_locked, begin, &kernel, ppool)) {
		dlog("Unable to copy kernel.\n");
		return false;
	}

	return true;
}

/**
 * Loads the primary VM.
 */
static bool load_primary(struct mm_stage1_locked stage1_locked,
			 const struct manifest *manifest,
			 const struct memiter *cpio,
			 const struct boot_params *params, struct mpool *ppool)
{
	paddr_t primary_begin = layout_primary_begin();
	struct vm *vm;
	struct vcpu_locked vcpu_locked;
	size_t i;

	/*
	 * TODO: This bound is currently meaningless but will be addressed when
	 * the manifest specifies the load address.
	 */
	paddr_t primary_end = pa_add(primary_begin, 0x8000000);

	if (!load_kernel(stage1_locked, primary_begin, primary_end,
			 &manifest->vm[HF_PRIMARY_VM_INDEX], cpio, ppool)) {
		dlog("Unable to load primary kernel.");
		return false;
	}

	if (!vm_init(MAX_CPUS, ppool, &vm)) {
		dlog("Unable to initialise primary vm\n");
		return false;
	}

	if (vm->id != HF_PRIMARY_VM_ID) {
		dlog("Primary vm was not given correct id\n");
		return false;
	}

	/*
	 * Map 1TB of address space as device memory to, most likely, make all
	 * devices available to the primary VM.
	 *
	 * TODO: We should do a whitelist rather than a blacklist.
	 */
	if (!mm_vm_identity_map(&vm->ptable, pa_init(0),
				pa_init(UINT64_C(1024) * 1024 * 1024 * 1024),
				MM_MODE_R | MM_MODE_W | MM_MODE_D, NULL,
				ppool)) {
		dlog("Unable to initialise address space for primary vm\n");
		return false;
	}

	/* Map normal memory as such to permit caching, execution, etc. */
	for (i = 0; i < params->mem_ranges_count; ++i) {
		if (!mm_vm_identity_map(
			    &vm->ptable, params->mem_ranges[i].begin,
			    params->mem_ranges[i].end,
			    MM_MODE_R | MM_MODE_W | MM_MODE_X, NULL, ppool)) {
			dlog("Unable to initialise memory for primary vm\n");
			return false;
		}
	}

	if (!mm_vm_unmap_hypervisor(&vm->ptable, ppool)) {
		dlog("Unable to unmap hypervisor from primary vm\n");
		return false;
	}

	vcpu_locked = vcpu_lock(vm_get_vcpu(vm, 0));
	vcpu_on(vcpu_locked, ipa_from_pa(primary_begin), params->kernel_arg);
	vcpu_unlock(&vcpu_locked);

	return true;
}

/*
 * Loads a secondary VM.
 */
static bool load_secondary(struct mm_stage1_locked stage1_locked,
			   paddr_t mem_begin, paddr_t mem_end,
			   const struct manifest_vm *manifest_vm,
			   const struct memiter *cpio, struct mpool *ppool)
{
	struct vm *vm;
	struct vcpu *vcpu;
	ipaddr_t secondary_entry;

	if (!load_kernel(stage1_locked, mem_begin, mem_end, manifest_vm, cpio,
			 ppool)) {
		dlog("Unable to load kernel.\n");
		return false;
	}

	if (!vm_init(manifest_vm->secondary.vcpu_count, ppool, &vm)) {
		dlog("Unable to initialise VM.\n");
		return false;
	}

	/* Grant the VM access to the memory. */
	if (!mm_vm_identity_map(&vm->ptable, mem_begin, mem_end,
				MM_MODE_R | MM_MODE_W | MM_MODE_X,
				&secondary_entry, ppool)) {
		dlog("Unable to initialise memory.\n");
		return false;
	}

	dlog("Loaded with %u vcpus, entry at %#x.\n",
	     manifest_vm->secondary.vcpu_count, pa_addr(mem_begin));

	vcpu = vm_get_vcpu(vm, 0);
	vcpu_secondary_reset_and_start(vcpu, secondary_entry,
				       pa_difference(mem_begin, mem_end));

	return true;
}

/**
 * Try to find a memory range of the given size within the given ranges, and
 * remove it from them. Return true on success, or false if no large enough
 * contiguous range is found.
 */
static bool carve_out_mem_range(struct mem_range *mem_ranges,
				size_t mem_ranges_count, uint64_t size_to_find,
				paddr_t *found_begin, paddr_t *found_end)
{
	size_t i;

	/*
	 * TODO(b/116191358): Consider being cleverer about how we pack VMs
	 * together, with a non-greedy algorithm.
	 */
	for (i = 0; i < mem_ranges_count; ++i) {
		if (size_to_find <=
		    pa_difference(mem_ranges[i].begin, mem_ranges[i].end)) {
			/*
			 * This range is big enough, take some of it from the
			 * end and reduce its size accordingly.
			 */
			*found_end = mem_ranges[i].end;
			*found_begin = pa_init(pa_addr(mem_ranges[i].end) -
					       size_to_find);
			mem_ranges[i].end = *found_begin;
			return true;
		}
	}
	return false;
}

/**
 * Given arrays of memory ranges before and after memory was removed for
 * secondary VMs, add the difference to the reserved ranges of the given update.
 * Return true on success, or false if there would be more than MAX_MEM_RANGES
 * reserved ranges after adding the new ones.
 * `before` and `after` must be arrays of exactly `mem_ranges_count` elements.
 */
static bool update_reserved_ranges(struct boot_params_update *update,
				   const struct mem_range *before,
				   const struct mem_range *after,
				   size_t mem_ranges_count)
{
	size_t i;

	for (i = 0; i < mem_ranges_count; ++i) {
		if (pa_addr(after[i].begin) > pa_addr(before[i].begin)) {
			if (update->reserved_ranges_count >= MAX_MEM_RANGES) {
				dlog("Too many reserved ranges after loading "
				     "secondary VMs.\n");
				return false;
			}
			update->reserved_ranges[update->reserved_ranges_count]
				.begin = before[i].begin;
			update->reserved_ranges[update->reserved_ranges_count]
				.end = after[i].begin;
			update->reserved_ranges_count++;
		}
		if (pa_addr(after[i].end) < pa_addr(before[i].end)) {
			if (update->reserved_ranges_count >= MAX_MEM_RANGES) {
				dlog("Too many reserved ranges after loading "
				     "secondary VMs.\n");
				return false;
			}
			update->reserved_ranges[update->reserved_ranges_count]
				.begin = after[i].end;
			update->reserved_ranges[update->reserved_ranges_count]
				.end = before[i].end;
			update->reserved_ranges_count++;
		}
	}

	return true;
}

/*
 * Loads alls VMs from the manifest.
 */
bool load_vms(struct mm_stage1_locked stage1_locked,
	      const struct manifest *manifest, const struct memiter *cpio,
	      const struct boot_params *params,
	      struct boot_params_update *update, struct mpool *ppool)
{
	struct vm *primary;
	struct mem_range mem_ranges_available[MAX_MEM_RANGES];
	size_t i;

	if (!load_primary(stage1_locked, manifest, cpio, params, ppool)) {
		dlog("Unable to load primary VM.\n");
		return false;
	}

	static_assert(
		sizeof(mem_ranges_available) == sizeof(params->mem_ranges),
		"mem_range arrays must be the same size for memcpy.");
	static_assert(sizeof(mem_ranges_available) < 500,
		      "This will use too much stack, either make "
		      "MAX_MEM_RANGES smaller or change this.");
	memcpy_s(mem_ranges_available, sizeof(mem_ranges_available),
		 params->mem_ranges, sizeof(params->mem_ranges));

	primary = vm_find(HF_PRIMARY_VM_ID);

	/* Round the last addresses down to the page size. */
	for (i = 0; i < params->mem_ranges_count; ++i) {
		mem_ranges_available[i].end = pa_init(align_down(
			pa_addr(mem_ranges_available[i].end), PAGE_SIZE));
	}

	for (i = 0; i < manifest->vm_count; ++i) {
		const struct manifest_vm *manifest_vm = &manifest->vm[i];
		spci_vm_id_t vm_id = HF_VM_ID_OFFSET + i;
		uint64_t mem_size;
		paddr_t secondary_mem_begin;
		paddr_t secondary_mem_end;

		if (vm_id == HF_PRIMARY_VM_ID) {
			continue;
		}

		dlog("Loading VM%d: %s.\n", (int)vm_id,
		     manifest_vm->debug_name);

		mem_size = align_up(manifest_vm->secondary.mem_size, PAGE_SIZE);
		if (!carve_out_mem_range(mem_ranges_available,
					 params->mem_ranges_count, mem_size,
					 &secondary_mem_begin,
					 &secondary_mem_end)) {
			dlog("Not enough memory (%u bytes).\n", mem_size);
			continue;
		}

		if (!load_secondary(stage1_locked, secondary_mem_begin,
				    secondary_mem_end, manifest_vm, cpio,
				    ppool)) {
			dlog("Unable to load VM.\n");
			continue;
		}

		/* Deny the primary VM access to this memory. */
		if (!mm_vm_unmap(&primary->ptable, secondary_mem_begin,
				 secondary_mem_end, ppool)) {
			dlog("Unable to unmap secondary VM from primary VM.\n");
			return false;
		}
	}

	/*
	 * Add newly reserved areas to update params by looking at the
	 * difference between the available ranges from the original params and
	 * the updated mem_ranges_available. We assume that the number and order
	 * of available ranges is the same, i.e. we don't remove any ranges
	 * above only make them smaller.
	 */
	return update_reserved_ranges(update, params->mem_ranges,
				      mem_ranges_available,
				      params->mem_ranges_count);
}
