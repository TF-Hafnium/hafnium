/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

/**
 * Set architecture-specific features for the specified VM.
 */
void arch_vm_features_set(struct vm *vm);
bool arch_vm_init_mm(struct vm *vm, struct mpool *ppool);
bool arch_vm_iommu_init_mm(struct vm *vm, struct mpool *ppool);
bool arch_vm_identity_prepare(struct vm_locked vm_locked, paddr_t begin,
			      paddr_t end, uint32_t mode, struct mpool *ppool);
void arch_vm_identity_commit(struct vm_locked vm_locked, paddr_t begin,
			     paddr_t end, uint32_t mode, struct mpool *ppool,
			     ipaddr_t *ipa);
bool arch_vm_unmap(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
		   struct mpool *ppool);
void arch_vm_ptable_defrag(struct vm_locked vm_locked, struct mpool *ppool);
bool arch_vm_mem_get_mode(struct vm_locked vm_locked, ipaddr_t begin,
			  ipaddr_t end, uint32_t *mode);
bool arch_vm_iommu_mm_identity_map(struct vm_locked vm_locked, paddr_t begin,
				   paddr_t end, uint32_t mode,
				   struct mpool *ppool, ipaddr_t *ipa,
				   uint8_t dma_device_id);
