/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/check.h"
#include "hf/mm.h"
#include "hf/types.h"

#define SP_PKG_HEADER_MAGIC 0x474b5053U
#define SP_PKG_HEADER_VERSION_1 0x1U
#define SP_PKG_HEADER_VERSION_2 0x2U

#define SP_PKG_FLAG_BOOT_INFO (UINT32_C(1) << 0)

/**
 *  Header for a SP Partition Package.
 */
struct sp_pkg_header {
	/** Magic used to identify a SP package. Value is "SPKG". */
	uint32_t magic;
	/** Version number of the header. */
	uint32_t version;
	/** Offset in bytes to the partition manifests. */
	uint32_t pm_offset;
	/** Size in bytes of the partition manifest. */
	uint32_t pm_size;
	/** Offset in bytes to the base address of the partition binary. */
	uint32_t img_offset;
	/** Size in bytes of the partition binary. */
	uint32_t img_size;
};

static inline size_t sp_pkg_get_mem_size(struct sp_pkg_header *sp_pkg)
{
	assert(SIZE_MAX - sp_pkg->img_offset >= (size_t)sp_pkg->img_size);
	return (sp_pkg->img_offset + sp_pkg->img_size);
}

/** Get the size of the boot information descriptors section. */
static inline size_t sp_pkg_get_boot_info_size(struct sp_pkg_header *sp_pkg)
{
	return sp_pkg->pm_offset;
}

bool sp_pkg_init(struct mm_stage1_locked stage1_locked, paddr_t pkg_start,
		 struct sp_pkg_header *header, struct mpool *ppool);

void sp_pkg_deinit(struct mm_stage1_locked stage1_locked, vaddr_t pkg_start,
		   struct sp_pkg_header *header, struct mpool *ppool);
