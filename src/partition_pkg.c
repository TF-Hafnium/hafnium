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
