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

/**
 * Function initializes the Secure Partition Package version 0x1:
 * - Partition manifest is at offset configured in the package header.
 * - Image offset expected to be 4kb aligned, and to follow the pm manifest.
 */
static bool sp_pkg_init_v1(struct mm_stage1_locked stage1_locked,
			   paddr_t pkg_start, struct sp_pkg_header *header,
			   struct mpool *ppool)
{
	size_t manifest_size;

	assert(header != NULL);

	/* Expect DTB to immediately follow header */
	if (header->pm_offset != sizeof(struct sp_pkg_header)) {
		dlog_error("Invalid package manifest offset.\n");
		return false;
	}

	if ((header->img_offset % PAGE_SIZE) != 0U) {
		dlog_error("Image offset in SP pkg is not page aligned.\n");
		return false;
	}

	manifest_size = align_up(header->pm_size + sizeof(struct sp_pkg_header),
				 PAGE_SIZE);

	/* Check that the pm shouldn't override the image. */
	if (manifest_size > header->img_offset) {
		dlog_error("Partition manifest bigger than its region.\n");
		return false;
	}

	/*
	 * Map remainder of header + manifest. This assumes that PAGE_SIZE has
	 * been mapped already, prior to calling this function.
	 */
	if (manifest_size > PAGE_SIZE) {
		CHECK(mm_identity_map(stage1_locked, pkg_start,
				      pa_add(pkg_start, manifest_size),
				      MM_MODE_R, ppool));
	}

	return true;
}

/*
 * Function initializes the Secure Partition Package version 0x2:
 * - Maps whole region up to image such that Hafnium can parse the FF-A manifest
 * and can use the first chunk of memory for booting purposes.
 */
static bool sp_pkg_init_v2(struct mm_stage1_locked stage1_locked,
			   paddr_t pkg_start, struct sp_pkg_header *header,
			   struct mpool *ppool)
{
	assert(header != NULL);
	(void)pkg_start;
	(void)ppool;
	(void)stage1_locked;

	if (header->pm_offset % PAGE_SIZE != 0 ||
	    header->img_offset % PAGE_SIZE != 0) {
		dlog_error("SP pkg offsets are not page aligned.\n");
		return false;
	}

	if (header->pm_offset > header->img_offset) {
		dlog_error(
			"SP pkg offsets must be in order: boot info < "
			"partition manifest < image offset.\n");
		return false;
	}

	/*
	 * Check for overflow and then check the pm shouldn't override the
	 * image.
	 */
	assert(UINT32_MAX - header->pm_offset >= header->pm_size);
	if (header->pm_offset + header->pm_size > header->img_offset) {
		dlog_error("Partition manifest bigger than its region.\n");
		return false;
	}

	return true;
}

/**
 * Initializes the Secure Partition Package. It relies on helper functions
 * for the respective versions 1 and 2. Returns true if the initialization goes
 * well, otherwise returns false.
 */
bool sp_pkg_init(struct mm_stage1_locked stage1_locked, paddr_t pkg_start,
		 struct sp_pkg_header *header, struct mpool *ppool)
{
	/*
	 * Assumes the page the first page of the package, has been mapped
	 * already.
	 */
	memcpy_s(header, sizeof(struct sp_pkg_header),
		 ptr_from_va(va_from_pa(pkg_start)),
		 sizeof(struct sp_pkg_header));

	switch (header->version) {
	case SP_PKG_HEADER_VERSION_1:
		if (sp_pkg_init_v1(stage1_locked, pkg_start, header, ppool)) {
			return true;
		}
		break;
	case SP_PKG_HEADER_VERSION_2:
		if (sp_pkg_init_v2(stage1_locked, pkg_start, header, ppool)) {
			return true;
		}
		break;
	default:
		dlog_error("%s: Unrecognized Secure Partition Pkg format.\n",
			   __func__);
	}

	return false;
}
