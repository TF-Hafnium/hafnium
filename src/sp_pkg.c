/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/sp_pkg.h"

#include <stdint.h>

#include "hf/arch/std.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/std.h"

/*
 * Function initializes the Secure Partition Package:
 * - Maps whole region up to image such that Hafnium can parse the FF-A manifest
 * and can use the first chunk of memory for booting purposes.
 */
bool sp_pkg_init(struct mm_stage1_locked stage1_locked, paddr_t pkg_start,
		 struct sp_pkg_header *header, struct mpool *ppool)
{
	bool ret = false;
	paddr_t pkg_end = pa_add(pkg_start, PAGE_SIZE);
	void *pkg;

	/* Firstly, map a single page of package header. */
	pkg = mm_identity_map(stage1_locked, pkg_start, pkg_end,
			      MM_MODE_R | MM_MODE_W, ppool);
	assert(pkg != NULL);

	memcpy_s(header, sizeof(struct sp_pkg_header), pkg,
		 sizeof(struct sp_pkg_header));

	if (header->magic != SP_PKG_HEADER_MAGIC) {
		dlog_error("Invalid package magic.\n");
		goto exit_unmap;
	}

	if (header->version != SP_PKG_HEADER_VERSION) {
		dlog_error("Invalid package version.\n");
		goto exit_unmap;
	}

	if (header->pm_offset % PAGE_SIZE != 0 ||
	    header->img_offset % PAGE_SIZE != 0) {
		dlog_error("SP pkg offsets are not page aligned.\n");
		goto exit_unmap;
	}

	if (header->pm_offset > header->img_offset) {
		dlog_error(
			"SP pkg offsets must be in order: boot info < "
			"partition manifest < image offset.\n");
		goto exit_unmap;
	}

	/*
	 * Check for overflow and then check the pm shouldn't override the
	 * image.
	 */
	assert(UINT32_MAX - header->pm_offset >= header->pm_size);
	if (header->pm_offset + header->pm_size > header->img_offset) {
		dlog_error("Partition manifest bigger than its region.\n");
		goto exit_unmap;
	}

	/*
	 * Remap section up to pm as RW, to allow for writing of boot info
	 * descriptors, if the SP specified boot info in its manifest.
	 */
	if (header->pm_offset > PAGE_SIZE) {
		pkg_end = pa_add(pkg_start, header->pm_offset);
		CHECK(mm_identity_map(stage1_locked, pkg_start, pkg_end,
				      MM_MODE_R | MM_MODE_W, ppool) != NULL);
	}

	CHECK(mm_identity_map(stage1_locked, pkg_end,
			      pa_add(pkg_end, header->pm_size), MM_MODE_R,
			      ppool) != NULL);

	ret = true;

exit_unmap:
	if (!ret) {
		CHECK(mm_unmap(stage1_locked, pkg_start, pkg_end, ppool));
	}

	return ret;
}

/**
 * Unmap SP Pkg from Hafnium's address space.
 */
void sp_pkg_deinit(struct mm_stage1_locked stage1_locked, vaddr_t pkg_start,
		   struct sp_pkg_header *header, struct mpool *ppool)
{
	paddr_t to_unmap_end;

	to_unmap_end = pa_from_va(
		va_add(pkg_start, header->pm_offset + header->pm_size));

	CHECK(mm_unmap(stage1_locked, pa_from_va(pkg_start), to_unmap_end,
		       ppool));
}
