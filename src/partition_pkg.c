/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/partition_pkg.h"

#include <stdint.h>

#include "hf/arch/std.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/mm.h"
#include "hf/sp_pkg.h"
#include "hf/std.h"
#include "hf/transfer_list.h"

static void dump_partition_package(struct partition_pkg *pkg)
{
	dlog_verbose("%s: total %lx %lx\n", __func__, pa_addr(pkg->total.begin),
		     pa_addr(pkg->total.end));
	dlog_verbose("%s: pm: %lx %lx\n", __func__, pa_addr(pkg->pm.begin),
		     pa_addr(pkg->pm.end));
	dlog_verbose("%s: img: %lx %lx\n", __func__, pa_addr(pkg->img.begin),
		     pa_addr(pkg->img.end));
	dlog_verbose("%s: boot_info: %lx %lx\n", __func__,
		     pa_addr(pkg->boot_info.begin),
		     pa_addr(pkg->boot_info.end));
	if (mem_range_is_valid(pkg->hob)) {
		dlog_verbose("%s: hob %lx %lx\n", __func__,
			     pa_addr(pkg->hob.begin), pa_addr(pkg->hob.end));
	}
}

static bool partition_pkg_from_sp_pkg(struct mm_stage1_locked stage1_locked,
				      paddr_t pkg_start,
				      struct partition_pkg *pkg,
				      struct mpool *ppool)
{
	struct sp_pkg_header header;
	bool ret = sp_pkg_init(stage1_locked, pkg_start, &header, ppool);
	size_t total_mem_size = sp_pkg_get_mem_size(&header);

	pkg->total.begin = pkg_start;
	pkg->total.end = pa_add(pkg_start, total_mem_size);

	pkg->pm.begin = pa_add(pkg_start, header.pm_offset);
	pkg->pm.end = pa_add(pkg->pm.begin, header.pm_size);

	pkg->img.begin = pa_add(pkg_start, header.img_offset);
	pkg->img.end = pa_add(pkg->img.begin, header.img_size);

	/*
	 * Repurpose the first page of the SP Package.
	 * FF-A boot info will overwrite the package, but it doesn't
	 * matter at this stage, given Hafnium already parsed it.
	 */
	pkg->boot_info.begin = pkg_start;
	pkg->boot_info.end = pa_add(pkg_start, header.pm_offset);

	/* HOB section doesn't exist in the SP Pkg type. */
	pkg->hob.begin = pa_init(0);
	pkg->hob.end = pa_init(0);

	dump_partition_package(pkg);

	/* Map the whole package as RO. */
	CHECK(mm_identity_map(stage1_locked, pkg->total.begin, pkg->total.end,
			      MM_MODE_R, ppool) != NULL);

	return ret;
}

/**
 * It creates a memory range structure which relates to the region of the
 * TE data.
 * It returns false if there is no TE entry with the specified type.
 * It returns true, if there is a TE entry with the specified type, and
 * returns the memory range via `mem_range`.
 */
static bool partition_pkg_init_memory_range_from_te(
	struct mem_range *mem_range, struct transfer_list_entry *te)
{
	void *te_data;

	assert(mem_range != NULL);

	te_data = transfer_list_entry_data(te);

	if (te == NULL || te_data == NULL) {
		mem_range->begin = pa_init(0);
		mem_range->end = pa_init(0);
		return false;
	}

	mem_range->begin = pa_from_va(va_init((uintptr_t)te_data));
	mem_range->end = pa_add(mem_range->begin, te->data_size);

	return true;
}

static bool partition_pkg_from_tl(struct mm_stage1_locked stage1_locked,
				  paddr_t pkg_start, struct partition_pkg *pkg,
				  struct mpool *ppool)
{
	struct transfer_list_header *tl = ptr_from_va(va_from_pa(pkg_start));
	enum transfer_list_ops tl_res;

	dlog_verbose("%s: partition loaded in a transfer list.\n", __func__);

	/* The total memory for the partition package. */
	pkg->total.begin = pkg_start;
	pkg->total.end = pa_add(pkg_start, tl->size);

	/* Map the whole TL as RO. */
	CHECK(mm_identity_map(stage1_locked, pkg->total.begin, pkg->total.end,
			      MM_MODE_R, ppool));

	tl_res = transfer_list_check_header(tl);

	if (tl_res == TL_OPS_NON || tl_res == TL_OPS_CUS) {
		return false;
	}

	/*
	 * Get the memory ranges from the TL for:
	 * - FFA_MANIFEST.
	 * - Partition Image.
	 */
	if (!partition_pkg_init_memory_range_from_te(
		    &(pkg->pm),
		    transfer_list_find(tl, TL_TAG_DT_FFA_MANIFEST)) ||
	    !partition_pkg_init_memory_range_from_te(
		    &(pkg->img),
		    transfer_list_find(tl, TL_TAG_FFA_SP_BINARY))) {
		return false;
	}

	/* An HOB entry is optional. */
	partition_pkg_init_memory_range_from_te(
		&(pkg->hob), transfer_list_find(tl, TL_TAG_HOB_LIST));

	if (!mem_range_aligns(pkg->pm, PAGE_SIZE)) {
		dlog_error(
			"%s: the partition manifest range must be 4k page "
			"aligned.\n",
			__func__);
		return false;
	}

	if (!mem_range_aligns(pkg->img, PAGE_SIZE)) {
		dlog_error(
			"%s: the partition image range must be 4k page "
			"aligned.\n",
			__func__);
		return false;
	}

	if (mem_range_is_valid(pkg->hob) &&
	    !mem_range_aligns(pkg->hob, PAGE_SIZE)) {
		dlog_error("%s: the hob range must be 4k page aligned.\n",
			   __func__);
		return false;
	}

	/*
	 * For the boot information descriptor, repurpose the TL's first page.
	 * The TL is only processed by Hafnium, and all items are placed at
	 * a page aligned offset.
	 * At this point, all references to artefacts in the TL have been
	 * obtained so the first page of the package can be repurposed to the
	 * FF-A boot information. There is no expectation that the boot info
	 * descriptors will need more than a page for the time being. If it does
	 * get full, Hafnium will fail at populating the boot info descriptors.
	 */
	pkg->boot_info.begin = pkg_start;
	pkg->boot_info.end = pa_add(pkg_start, PAGE_SIZE);

	dump_partition_package(pkg);

	return true;
}

bool partition_pkg_init(struct mm_stage1_locked stage1_locked,
			paddr_t pkg_start, struct partition_pkg *pkg,
			struct mpool *ppool)
{
	bool ret = false;
	paddr_t pkg_first_page = pa_add(pkg_start, PAGE_SIZE);
	uint32_t *magic;
	void *mapped_ptr;

	/* Firstly, map a single page to be able to read package header. */
	mapped_ptr = mm_identity_map(stage1_locked, pkg_start, pkg_first_page,
				     MM_MODE_R, ppool);
	assert(mapped_ptr != NULL);
	assert(pkg != NULL);

	magic = (uint32_t *)mapped_ptr;

	switch (*magic) {
	case SP_PKG_HEADER_MAGIC:
		/*
		 * Leave memory mapped in case it succeeded, to be cleared
		 * later.
		 */
		if (!partition_pkg_from_sp_pkg(stage1_locked, pkg_start, pkg,
					       ppool)) {
			goto out;
		}
		break;
	case TRANSFER_LIST_SIGNATURE:
		if (!partition_pkg_from_tl(stage1_locked, pkg_start, pkg,
					   ppool)) {
			goto out;
		}
		break;
	default:
		dlog_error("%s: invalid secure partition package %x @ %lx\n",
			   __func__, *magic, (uint64_t)magic);
		goto out;
	}

	dump_partition_package(pkg);

	/**
	 * The total memory range should encompass the remaining.
	 * Assert that none of the memory ranges are out of bounds.
	 */
	assert(mem_range_contains_range(pkg->total, pkg->img));
	assert(mem_range_contains_range(pkg->total, pkg->pm));
	assert(mem_range_contains_range(pkg->total, pkg->boot_info));
	assert(!mem_range_is_valid(pkg->hob) ||
	       mem_range_contains_range(pkg->total, pkg->hob));

	/* Map Boot info section as RW. */
	if (pa_addr(pkg->boot_info.begin) != 0U &&
	    pa_addr(pkg->boot_info.end) != 0U) {
		CHECK(mm_identity_map(stage1_locked, pkg->boot_info.begin,
				      pkg->boot_info.end, MM_MODE_R | MM_MODE_W,
				      ppool) != NULL);
	}

	ret = true;

out:
	/* If failing unmap the memory. */
	if (!ret) {
		CHECK(mm_unmap(stage1_locked, pkg_start, pkg_first_page,
			       ppool));
	}

	return ret;
}

void partition_pkg_deinit(struct mm_stage1_locked stage1_locked,
			  struct partition_pkg *pkg, struct mpool *ppool)
{
	CHECK(mm_unmap(stage1_locked, pkg->total.begin, pkg->total.end, ppool));
}
