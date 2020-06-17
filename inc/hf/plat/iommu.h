/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/fdt.h"
#include "hf/vm.h"

/**
 * Initializes the platform IOMMU driver. The root node of the FDT is provided
 * so that the driver can read from it. This can be used to map IOMMU devices
 * into the hypervisor's address space so they are accessible by the driver.
 */
bool plat_iommu_init(const struct fdt *fdt,
		     struct mm_stage1_locked stage1_locked,
		     struct mpool *ppool);

/**
 * Unmaps the address space used by the platform IOMMU driver from the VM so
 * that VM cannot program these devices.
 *
 * Note that any calls to unmap an address range will result in
 * `plat_iommu_identity_map` being invoked to apply the change to the IOMMU
 * mapping as well. The module must ensure it can handle this reentrancy.
 */
bool plat_iommu_unmap_iommus(struct vm_locked vm_locked, struct mpool *ppool);

/**
 * Maps the address range with the given mode for the given VM in the IOMMU.
 *
 * Assumes the identity map cannot fail. This may not always be true and if it
 * isn't it will require careful thought on how to safely handle error cases
 * when intermingled with MMU updates but it gives a starting point for drivers
 * until those problems are understood.
 *
 * The modes are the same as the memory management modes but it is only required
 * that read and write modes are enforced by the IOMMU driver.
 */
void plat_iommu_identity_map(struct vm_locked vm_locked, paddr_t begin,
			     paddr_t end, uint32_t mode);
