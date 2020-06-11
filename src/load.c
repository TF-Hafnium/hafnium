/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/load.h"

#include <stdbool.h>

#include "hf/arch/vm.h"

#include "hf/api.h"
#include "hf/boot_params.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/fdt_patch.h"
#include "hf/layout.h"
#include "hf/memiter.h"
#include "hf/mm.h"
#include "hf/plat/console.h"
#include "hf/plat/iommu.h"
#include "hf/static_assert.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

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

/**
 * Loads the secondary VM's kernel.
 * Stores the kernel size in kernel_size (if kernel_size is not NULL).
 * Returns false if it cannot load the kernel.
 */
static bool load_kernel(struct mm_stage1_locked stage1_locked, paddr_t begin,
			paddr_t end, const struct manifest_vm *manifest_vm,
			const struct memiter *cpio, struct mpool *ppool,
			size_t *kernel_size)
{
	struct memiter kernel;
	size_t size;

	if (!cpio_get_file(cpio, &manifest_vm->kernel_filename, &kernel)) {
		dlog_error("Could not find kernel file \"%s\".\n",
			   string_data(&manifest_vm->kernel_filename));
		return false;
	}

	size = memiter_size(&kernel);
	if (pa_difference(begin, end) < size) {
		dlog_error("Kernel is larger than available memory.\n");
		return false;
	}

	if (!copy_to_unmapped(stage1_locked, begin, &kernel, ppool)) {
		dlog_error("Unable to copy kernel.\n");
		return false;
	}

	if (kernel_size) {
		*kernel_size = size;
	}

	return true;
}

/*
 * Link RX/TX buffers provided in partition manifest to mailbox
 */
static bool link_rxtx_to_mailbox(struct mm_stage1_locked stage1_locked,
				 struct vm_locked vm_locked, struct rx_tx rxtx,
				 struct mpool *ppool)
{
	struct ffa_value ret;
	ipaddr_t send;
	ipaddr_t recv;
	uint32_t page_count;

	send = ipa_init(rxtx.tx_buffer->base_address);
	recv = ipa_init(rxtx.rx_buffer->base_address);
	page_count = rxtx.tx_buffer->page_count;

	ret = api_vm_configure_pages(stage1_locked, vm_locked, send, recv,
				     page_count, ppool);
	if (ret.func != FFA_SUCCESS_32) {
		return false;
	}

	dlog_verbose("  mailbox: send = %#x, recv = %#x\n",
		     vm_locked.vm->mailbox.send, vm_locked.vm->mailbox.recv);

	return true;
}

/**
 * Performs VM loading activities that are common between the primary and
 * secondaries.
 */
static bool load_common(struct mm_stage1_locked stage1_locked,
			struct vm_locked vm_locked,
			const struct manifest_vm *manifest_vm,
			struct mpool *ppool)
{
	vm_locked.vm->smc_whitelist = manifest_vm->smc_whitelist;
	vm_locked.vm->uuid = manifest_vm->sp.uuid;

	if (manifest_vm->is_ffa_partition) {
		/* Link rxtx buffers to mailbox */
		if (manifest_vm->sp.rxtx.available) {
			if (!link_rxtx_to_mailbox(stage1_locked, vm_locked,
						  manifest_vm->sp.rxtx,
						  ppool)) {
				dlog_error(
					"Unable to Link RX/TX buffer with "
					"mailbox.\n");
				return false;
			}
		}
	}
	/* Initialize architecture-specific features. */
	arch_vm_features_set(vm_locked.vm);

	return true;
}

/**
 * Loads the primary VM.
 */
static bool load_primary(struct mm_stage1_locked stage1_locked,
			 const struct manifest_vm *manifest_vm,
			 const struct memiter *cpio,
			 const struct boot_params *params, struct mpool *ppool)
{
	paddr_t primary_begin;
	ipaddr_t primary_entry;
	struct vm *vm;
	struct vm_locked vm_locked;
	struct vcpu_locked vcpu_locked;
	size_t i;
	bool ret;

	if (manifest_vm->is_ffa_partition) {
		primary_begin = pa_init(manifest_vm->sp.load_addr);
		primary_entry = ipa_add(ipa_from_pa(primary_begin),
					manifest_vm->sp.ep_offset);
	} else {
		primary_begin =
			(manifest_vm->primary.boot_address ==
			 MANIFEST_INVALID_ADDRESS)
				? layout_primary_begin()
				: pa_init(manifest_vm->primary.boot_address);
		primary_entry = ipa_from_pa(primary_begin);
	}

	paddr_t primary_end = pa_add(primary_begin, RSIZE_MAX);

	/*
	 * Load the kernel if a filename is specified in the VM manifest.
	 * For an FF-A partition, kernel_filename is undefined indicating
	 * the partition package has already been loaded prior to Hafnium
	 * booting.
	 */
	if (!string_is_empty(&manifest_vm->kernel_filename)) {
		if (!load_kernel(stage1_locked, primary_begin, primary_end,
				 manifest_vm, cpio, ppool, NULL)) {
			dlog_error("Unable to load primary kernel.\n");
			return false;
		}
	}

	if (!vm_init_next(MAX_CPUS, ppool, &vm)) {
		dlog_error("Unable to initialise primary VM.\n");
		return false;
	}

	if (vm->id != HF_PRIMARY_VM_ID) {
		dlog_error("Primary VM was not given correct ID.\n");
		return false;
	}

	vm_locked = vm_lock(vm);

	if (params->device_mem_ranges_count == 0) {
		/*
		 * Map 1TB of address space as device memory to, most likely,
		 * make all devices available to the primary VM.
		 *
		 * TODO: remove this once all targets provide valid ranges.
		 */
		dlog_warning(
			"Device memory not provided, defaulting to 1 TB.\n");

		if (!vm_identity_map(
			    vm_locked, pa_init(0),
			    pa_init(UINT64_C(1024) * 1024 * 1024 * 1024),
			    MM_MODE_R | MM_MODE_W | MM_MODE_D, ppool, NULL)) {
			dlog_error(
				"Unable to initialise address space for "
				"primary VM.\n");
			ret = false;
			goto out;
		}
	}

	/* Map normal memory as such to permit caching, execution, etc. */
	for (i = 0; i < params->mem_ranges_count; ++i) {
		if (!vm_identity_map(vm_locked, params->mem_ranges[i].begin,
				     params->mem_ranges[i].end,
				     MM_MODE_R | MM_MODE_W | MM_MODE_X, ppool,
				     NULL)) {
			dlog_error(
				"Unable to initialise memory for primary "
				"VM.\n");
			ret = false;
			goto out;
		}
	}

	/* Map device memory as such to prevent execution, speculation etc. */
	for (i = 0; i < params->device_mem_ranges_count; ++i) {
		if (!vm_identity_map(
			    vm_locked, params->device_mem_ranges[i].begin,
			    params->device_mem_ranges[i].end,
			    MM_MODE_R | MM_MODE_W | MM_MODE_D, ppool, NULL)) {
			dlog("Unable to initialise device memory for primary "
			     "VM.\n");
			ret = false;
			goto out;
		}
	}

	if (!load_common(stage1_locked, vm_locked, manifest_vm, ppool)) {
		ret = false;
		goto out;
	}

	if (!vm_unmap_hypervisor(vm_locked, ppool)) {
		dlog_error("Unable to unmap hypervisor from primary VM.\n");
		ret = false;
		goto out;
	}

	if (!plat_iommu_unmap_iommus(vm_locked, ppool)) {
		dlog_error("Unable to unmap IOMMUs from primary VM.\n");
		ret = false;
		goto out;
	}

	dlog_info("Loaded primary VM with %u vCPUs, entry at %#x.\n",
		  vm->vcpu_count, pa_addr(primary_begin));

	vcpu_locked = vcpu_lock(vm_get_vcpu(vm, 0));
	vcpu_on(vcpu_locked, primary_entry, params->kernel_arg);
	vcpu_unlock(&vcpu_locked);
	ret = true;

out:
	vm_unlock(&vm_locked);

	return ret;
}

/**
 * Loads the secondary VM's FDT.
 * Stores the total allocated size for the FDT in fdt_allocated_size (if
 * fdt_allocated_size is not NULL). The allocated size includes additional space
 * for potential patching.
 */
static bool load_secondary_fdt(struct mm_stage1_locked stage1_locked,
			       paddr_t end, size_t fdt_max_size,
			       const struct manifest_vm *manifest_vm,
			       const struct memiter *cpio, struct mpool *ppool,
			       paddr_t *fdt_addr, size_t *fdt_allocated_size)
{
	struct memiter fdt;
	size_t allocated_size;

	CHECK(!string_is_empty(&manifest_vm->secondary.fdt_filename));

	if (!cpio_get_file(cpio, &manifest_vm->secondary.fdt_filename, &fdt)) {
		dlog_error("Cannot open the secondary VM's FDT.\n");
		return false;
	}

	/*
	 * Ensure the FDT has one additional page at the end for patching, and
	 * and align it to the page boundary.
	 */
	allocated_size = align_up(memiter_size(&fdt), PAGE_SIZE) + PAGE_SIZE;

	if (allocated_size > fdt_max_size) {
		dlog_error(
			"FDT allocated space (%u) is more than the specified "
			"maximum to use (%u).\n",
			allocated_size, fdt_max_size);
		return false;
	}

	/* Load the FDT to the end of the VM's allocated memory space. */
	*fdt_addr = pa_init(pa_addr(pa_sub(end, allocated_size)));

	dlog_info("Loading secondary FDT of allocated size %u at 0x%x.\n",
		  allocated_size, pa_addr(*fdt_addr));

	if (!copy_to_unmapped(stage1_locked, *fdt_addr, &fdt, ppool)) {
		dlog_error("Unable to copy FDT.\n");
		return false;
	}

	if (fdt_allocated_size) {
		*fdt_allocated_size = allocated_size;
	}

	return true;
}

/*
 * Loads a secondary VM.
 */
static bool load_secondary(struct mm_stage1_locked stage1_locked,
			   struct vm_locked primary_vm_locked,
			   paddr_t mem_begin, paddr_t mem_end,
			   const struct manifest_vm *manifest_vm,
			   const struct memiter *cpio, struct mpool *ppool)
{
	struct vm *vm;
	struct vm_locked vm_locked;
	struct vcpu *vcpu;
	ipaddr_t secondary_entry;
	bool ret;
	paddr_t fdt_addr;
	bool has_fdt;
	size_t kernel_size = 0;
	const size_t mem_size = pa_difference(mem_begin, mem_end);

	/*
	 * Load the kernel if a filename is specified in the VM manifest.
	 * For an FF-A partition, kernel_filename is undefined indicating
	 * the partition package has already been loaded prior to Hafnium
	 * booting.
	 */
	if (!string_is_empty(&manifest_vm->kernel_filename)) {
		if (!load_kernel(stage1_locked, mem_begin, mem_end, manifest_vm,
				 cpio, ppool, &kernel_size)) {
			dlog_error("Unable to load kernel.\n");
			return false;
		}
	}

	has_fdt = !string_is_empty(&manifest_vm->secondary.fdt_filename);
	if (has_fdt) {
		/*
		 * Ensure that the FDT does not overwrite the kernel or overlap
		 * its page, for the FDT to start at a page boundary.
		 */
		const size_t fdt_max_size =
			mem_size - align_up(kernel_size, PAGE_SIZE);

		size_t fdt_allocated_size;

		if (!load_secondary_fdt(stage1_locked, mem_end, fdt_max_size,
					manifest_vm, cpio, ppool, &fdt_addr,
					&fdt_allocated_size)) {
			dlog_error("Unable to load FDT.\n");
			return false;
		}

		if (!fdt_patch_mem(stage1_locked, fdt_addr, fdt_allocated_size,
				   mem_begin, mem_end, ppool)) {
			dlog_error("Unable to patch FDT.\n");
			return false;
		}
	}

	if (!vm_init_next(manifest_vm->secondary.vcpu_count, ppool, &vm)) {
		dlog_error("Unable to initialise VM.\n");
		return false;
	}

	vm_locked = vm_lock(vm);

	/* Grant the VM access to the memory. */
	if (!vm_identity_map(vm_locked, mem_begin, mem_end,
			     MM_MODE_R | MM_MODE_W | MM_MODE_X, ppool,
			     &secondary_entry)) {
		dlog_error("Unable to initialise memory.\n");
		ret = false;
		goto out;
	}

	if (manifest_vm->is_ffa_partition) {
		int j = 0;
		paddr_t region_begin;
		paddr_t region_end;
		paddr_t alloc_base = mem_end;
		size_t size;
		size_t total_alloc = 0;

		/* Map memory-regions */
		while (j < manifest_vm->sp.mem_region_count) {
			size = manifest_vm->sp.mem_regions[j].page_count *
			       PAGE_SIZE;
			/*
			 * For memory-regions without base-address, memory
			 * should be allocated inside partition's page table.
			 * Start allocating memory regions in partition's
			 * page table, starting from the end.
			 * TODO: Add mechanism to let partition know of these
			 * memory regions
			 */
			if (manifest_vm->sp.mem_regions[j].base_address ==
			    MANIFEST_INVALID_ADDRESS) {
				total_alloc += size;
				/* Don't go beyond half the VM's memory space */
				if (total_alloc >
				    (manifest_vm->secondary.mem_size / 2)) {
					dlog_error(
						"Not enough space for memory-"
						"region allocation");
					ret = false;
					goto out;
				}

				region_end = alloc_base;
				region_begin = pa_subtract(alloc_base, size);
				alloc_base = region_begin;

				if (!vm_identity_map(
					    vm_locked, region_begin, region_end,
					    manifest_vm->sp.mem_regions[j]
						    .attributes,
					    ppool, NULL)) {
					dlog_error(
						"Unable to map secondary VM "
						"memory-region.\n");
					ret = false;
					goto out;
				}

				dlog_info(
					"  Memory region %#x - %#x allocated\n",
					region_begin, region_end);
			} else {
				/*
				 * Identity map memory region for both case,
				 * VA(S-EL0) or IPA(S-EL1).
				 */
				region_begin =
					pa_init(manifest_vm->sp.mem_regions[j]
							.base_address);
				region_end = pa_add(region_begin, size);

				if (!vm_identity_map(
					    vm_locked, region_begin, region_end,
					    manifest_vm->sp.mem_regions[j]
						    .attributes,
					    ppool, NULL)) {
					dlog_error(
						"Unable to map secondary VM "
						"memory-region.\n");
					ret = false;
					goto out;
				}
			}

			/* Deny the primary VM access to this memory */
			if (!vm_unmap(primary_vm_locked, region_begin,
				      region_end, ppool)) {
				dlog_error(
					"Unable to unmap secondary VM memory-"
					"region from primary VM.\n");
				ret = false;
				goto out;
			}

			j++;
		}

		/* Map device-regions */
		j = 0;
		while (j < manifest_vm->sp.dev_region_count) {
			region_begin = pa_init(
				manifest_vm->sp.dev_regions[j].base_address);
			size = manifest_vm->sp.dev_regions[j].page_count *
			       PAGE_SIZE;
			region_end = pa_add(region_begin, size);

			if (!vm_identity_map(
				    vm_locked, region_begin, region_end,
				    manifest_vm->sp.dev_regions[j].attributes,
				    ppool, NULL)) {
				dlog_error(
					"Unable to map secondary VM "
					"device-region.\n");
				ret = false;
				goto out;
			}
			/* Deny primary VM access to this region */
			if (!vm_unmap(primary_vm_locked, region_begin,
				      region_end, ppool)) {
				dlog_error(
					"Unable to unmap secondary VM device-"
					"region from primary VM.\n");
				ret = false;
				goto out;
			}
			j++;
		}

		secondary_entry =
			ipa_add(secondary_entry, manifest_vm->sp.ep_offset);
	}

	if (!load_common(stage1_locked, vm_locked, manifest_vm, ppool)) {
		ret = false;
		goto out;
	}

	dlog_info("Loaded with %u vCPUs, entry at %#x.\n",
		  manifest_vm->secondary.vcpu_count, pa_addr(mem_begin));

	vcpu = vm_get_vcpu(vm, 0);

	if (has_fdt) {
		vcpu_secondary_reset_and_start(vcpu, secondary_entry,
					       pa_addr(fdt_addr));
	} else {
		/*
		 * Without an FDT, secondary VMs expect the memory size to be
		 * passed in register x0, which is what
		 * vcpu_secondary_reset_and_start does in this case.
		 */
		vcpu_secondary_reset_and_start(vcpu, secondary_entry, mem_size);
	}

	ret = true;

out:
	vm_unlock(&vm_locked);

	return ret;
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
				dlog_error(
					"Too many reserved ranges after "
					"loading secondary VMs.\n");
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
				dlog_error(
					"Too many reserved ranges after "
					"loading secondary VMs.\n");
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
	struct vm *other_world_vm;
	struct mem_range mem_ranges_available[MAX_MEM_RANGES];
	struct vm_locked primary_vm_locked;
	size_t i;
	bool success = true;

	if (!load_primary(stage1_locked, &manifest->vm[HF_PRIMARY_VM_INDEX],
			  cpio, params, ppool)) {
		dlog_error("Unable to load primary VM.\n");
		return false;
	}

	/*
	 * Initialise the dummy VM which represents the opposite world:
	 * -TrustZone (or the SPMC) when running the Hypervisor
	 * -the Hypervisor when running TZ/SPMC
	 */
	other_world_vm = vm_init(HF_OTHER_WORLD_ID, MAX_CPUS, ppool);
	CHECK(other_world_vm != NULL);

	for (i = 0; i < MAX_CPUS; i++) {
		struct vcpu *vcpu = vm_get_vcpu(other_world_vm, i);
		struct cpu *cpu = cpu_find_index(i);

		vcpu->cpu = cpu;
	}

	static_assert(
		sizeof(mem_ranges_available) == sizeof(params->mem_ranges),
		"mem_range arrays must be the same size for memcpy.");
	static_assert(sizeof(mem_ranges_available) < 500,
		      "This will use too much stack, either make "
		      "MAX_MEM_RANGES smaller or change this.");
	memcpy_s(mem_ranges_available, sizeof(mem_ranges_available),
		 params->mem_ranges, sizeof(params->mem_ranges));

	/* Round the last addresses down to the page size. */
	for (i = 0; i < params->mem_ranges_count; ++i) {
		mem_ranges_available[i].end = pa_init(align_down(
			pa_addr(mem_ranges_available[i].end), PAGE_SIZE));
	}

	primary = vm_find(HF_PRIMARY_VM_ID);
	primary_vm_locked = vm_lock(primary);

	for (i = 0; i < manifest->vm_count; ++i) {
		const struct manifest_vm *manifest_vm = &manifest->vm[i];
		ffa_vm_id_t vm_id = HF_VM_ID_OFFSET + i;
		uint64_t mem_size;
		paddr_t secondary_mem_begin;
		paddr_t secondary_mem_end;

		if (vm_id == HF_PRIMARY_VM_ID) {
			continue;
		}

		dlog_info("Loading VM id %#x: %s.\n", vm_id,
			  manifest_vm->debug_name);

		mem_size = align_up(manifest_vm->secondary.mem_size, PAGE_SIZE);

		if (manifest_vm->is_ffa_partition) {
			secondary_mem_begin =
				pa_init(manifest_vm->sp.load_addr);
			secondary_mem_end =
				pa_init(manifest_vm->sp.load_addr + mem_size);
		} else if (!carve_out_mem_range(mem_ranges_available,
						params->mem_ranges_count,
						mem_size, &secondary_mem_begin,
						&secondary_mem_end)) {
			dlog_error("Not enough memory (%u bytes).\n", mem_size);
			continue;
		}

		if (!load_secondary(stage1_locked, primary_vm_locked,
				    secondary_mem_begin, secondary_mem_end,
				    manifest_vm, cpio, ppool)) {
			dlog_error("Unable to load VM.\n");
			continue;
		}

		/* Deny the primary VM access to this memory. */
		if (!vm_unmap(primary_vm_locked, secondary_mem_begin,
			      secondary_mem_end, ppool)) {
			dlog_error(
				"Unable to unmap secondary VM from primary "
				"VM.\n");
			success = false;
			break;
		}
	}

	vm_unlock(&primary_vm_locked);

	if (!success) {
		return false;
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
