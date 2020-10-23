/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/iommu.h"

bool plat_iommu_init(const struct fdt *fdt,
		     struct mm_stage1_locked stage1_locked, struct mpool *ppool)
{
	(void)fdt;
	(void)stage1_locked;
	(void)ppool;

	return true;
}

bool plat_iommu_unmap_iommus(struct vm_locked vm_locked, struct mpool *ppool)
{
	(void)vm_locked;
	(void)ppool;

	return true;
}

void plat_iommu_identity_map(struct vm_locked vm_locked, paddr_t begin,
			     paddr_t end, uint32_t mode)
{
	(void)vm_locked;
	(void)begin;
	(void)end;
	(void)mode;
}

bool plat_iommu_attach_peripheral(struct mm_stage1_locked stage1_locked,
				  struct vm_locked vm_locked,
				  const struct manifest_vm *manifest_vm,
				  struct mpool *ppool)
{
	(void)stage1_locked;
	(void)vm_locked;
	(void)manifest_vm;
	(void)ppool;

	return true;
}
