/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm.h"

#include "hf/arch/mmu.h"

#include "hf/dlog.h"

#include "hypervisor/feature_id.h"

void arch_vm_features_set(struct vm *vm)
{
	/* Features to trap for all VMs. */

	/*
	 * It is not safe to enable this yet, in part, because the feature's
	 * registers are not context switched in Hafnium.
	 */
	vm->arch.trapped_features |= HF_FEATURE_LOR;

	vm->arch.trapped_features |= HF_FEATURE_SPE;

	vm->arch.trapped_features |= HF_FEATURE_TRACE;

	vm->arch.trapped_features |= HF_FEATURE_DEBUG;

	vm->arch.trapped_features |= HF_FEATURE_SVE;

	vm->arch.trapped_features |= HF_FEATURE_SME;

	if (!vm_is_primary(vm)) {
		/*
		 * Features to trap only for the secondary VMs (and Secure
		 * Partitions).
		 */

		vm->arch.trapped_features |= HF_FEATURE_AMU;

		vm->arch.trapped_features |= HF_FEATURE_PERFMON;

		/*
		 * TODO(b/132395845): Access to RAS registers is not trapped at
		 * the moment for the primary VM, only for the secondaries. RAS
		 * register access isn't needed now, but it might be
		 * required for debugging. When Hafnium introduces debug vs
		 * release builds, trap accesses for primary VMs in release
		 * builds, but do not trap them in debug builds.
		 */
		vm->arch.trapped_features |= HF_FEATURE_RAS;

#if !BRANCH_PROTECTION
		/*
		 * When branch protection is enabled in the build
		 * (BRANCH_PROTECTION=1), the primary VM, secondary VMs and SPs
		 * are allowed to enable and use pointer authentication. When
		 * branch protection is disabled, only the primary VM is allowed
		 * to. Secondary VMs and SPs shall trap on accessing PAuth key
		 * registers.
		 */
		vm->arch.trapped_features |= HF_FEATURE_PAUTH;
#endif
	}
}

/*
 * Allow the partition manager to perform necessary steps to enforce access
 * control, with the help of IOMMU, for DMA accesses on behalf of a given
 * partition.
 */
bool arch_vm_iommu_init_mm(struct vm *vm, struct mpool *ppool)
{
	bool ret = true;

	/*
	 * No support to enforce access control through (stage 1) address
	 * translation for memory accesses by DMA device on behalf of an
	 * EL0/S-EL0 partition.
	 */
	if (vm->el0_partition) {
		return true;
	}

	for (uint8_t k = 0; k < vm->dma_device_count; k++) {
		/*
		 * Hafnium maintains an independent set of page tables for each
		 * DMA device that is upstream of given VM. This is necessary
		 * to enforce static DMA isolation.
		 */
		ret = ret &&
		      mm_ptable_init(&vm->iommu_ptables[k], vm->id, 0, ppool);
#if SECURE_WORLD == 1
		ret = ret && mm_ptable_init(&vm->arch.iommu_ptables_ns[k],
					    vm->id, 0, ppool);
#endif
		if (!ret) {
			dlog_error(
				"Failed to allocate entries for DMA page "
				"tables. Consider increasing heap page "
				"count.\n");
			return ret;
		}
	}

	return ret;
}

bool arch_vm_init_mm(struct vm *vm, struct mpool *ppool)
{
	bool ret;

	if (vm->el0_partition) {
		return mm_ptable_init(&vm->ptable, vm->id, MM_FLAG_STAGE1,
				      ppool);
	}

	ret = mm_vm_init(&vm->ptable, vm->id, ppool);

#if SECURE_WORLD == 1
	ret = ret && mm_vm_init(&vm->arch.ptable_ns, vm->id, ppool);
#endif

	return ret && arch_vm_iommu_init_mm(vm, ppool);
}

bool arch_vm_identity_prepare(struct vm_locked vm_locked, paddr_t begin,
			      paddr_t end, uint32_t mode, struct mpool *ppool)
{
	struct mm_ptable *table = &vm_locked.vm->ptable;

	if (vm_locked.vm->el0_partition) {
		return mm_identity_prepare(table, begin, end, mode, ppool);
	}

#if SECURE_WORLD == 1
	if (0 != (mode & MM_MODE_NS)) {
		table = &vm_locked.vm->arch.ptable_ns;
	}
#endif

	return mm_vm_identity_prepare(table, begin, end, mode, ppool);
}

void arch_vm_identity_commit(struct vm_locked vm_locked, paddr_t begin,
			     paddr_t end, uint32_t mode, struct mpool *ppool,
			     ipaddr_t *ipa)
{
	struct mm_ptable *table = &vm_locked.vm->ptable;

	if (vm_locked.vm->el0_partition) {
		mm_identity_commit(&vm_locked.vm->ptable, begin, end, mode,
				   ppool);
		if (ipa != NULL) {
			/*
			 * EL0 partitions are modeled as lightweight VM's, to
			 * promote code reuse. The below statement returns the
			 * mapped PA as an IPA, however, for an EL0 partition,
			 * this is really a VA.
			 */
			*ipa = ipa_from_pa(begin);
		}
	} else {
#if SECURE_WORLD == 1
		if (0 != (mode & MM_MODE_NS)) {
			table = &vm_locked.vm->arch.ptable_ns;
		}
#endif

		mm_vm_identity_commit(table, begin, end, mode, ppool, ipa);
	}
}

bool arch_vm_unmap(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
		   struct mpool *ppool)
{
	bool ret;
	uint32_t mode = MM_MODE_UNMAPPED_MASK;

	ret = vm_identity_map(vm_locked, begin, end, mode, ppool, NULL);

#if SECURE_WORLD == 1
	ret = ret && vm_identity_map(vm_locked, begin, end, mode | MM_MODE_NS,
				     ppool, NULL);
#endif

	return ret;
}

void arch_vm_ptable_defrag(struct vm_locked vm_locked, struct mpool *ppool)
{
	if (vm_locked.vm->el0_partition) {
		mm_stage1_defrag(&vm_locked.vm->ptable, ppool);
	} else {
		mm_vm_defrag(&vm_locked.vm->ptable, ppool, false);
#if SECURE_WORLD == 1
		/*
		 * TODO: check if this can be better optimized (pass the
		 * security state?).
		 */
		mm_vm_defrag(&vm_locked.vm->arch.ptable_ns, ppool, true);
#endif
	}
}

bool arch_vm_mem_get_mode(struct vm_locked vm_locked, ipaddr_t begin,
			  ipaddr_t end, uint32_t *mode)
{
	bool ret;

	if (vm_locked.vm->el0_partition) {
		return mm_get_mode(&vm_locked.vm->ptable,
				   va_from_pa(pa_from_ipa(begin)),
				   va_from_pa(pa_from_ipa(end)), mode);
	}

	ret = mm_vm_get_mode(&vm_locked.vm->ptable, begin, end, mode);

#if SECURE_WORLD == 1
	uint32_t mode2;
	const uint32_t mask =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;

	/* If the region is fully unmapped in the secure IPA space. */
	if ((ret == true) && ((*mode & mask) == mask)) {
		/* Look up the non-secure IPA space. */
		ret = mm_vm_get_mode(&vm_locked.vm->arch.ptable_ns, begin, end,
				     &mode2);

		/* If region is fully mapped in the non-secure IPA space. */
		if ((ret == true) && ((mode2 & mask) != mask)) {
			*mode = mode2;
		}
	}
#endif

	return ret;
}

static bool arch_vm_iommu_mm_prepare(struct vm_locked vm_locked, paddr_t begin,
				     paddr_t end, uint32_t mode,
				     struct mpool *ppool, uint8_t dma_device_id)
{
	struct mm_ptable *table = &vm_locked.vm->iommu_ptables[dma_device_id];

#if SECURE_WORLD == 1
	if (0 != (mode & MM_MODE_NS)) {
		table = &vm_locked.vm->arch.iommu_ptables_ns[dma_device_id];
	}
#endif

	return mm_vm_identity_prepare(table, begin, end, mode, ppool);
}

static void arch_vm_iommu_mm_commit(struct vm_locked vm_locked, paddr_t begin,
				    paddr_t end, uint32_t mode,
				    struct mpool *ppool, ipaddr_t *ipa,
				    uint8_t dma_device_id)
{
	struct mm_ptable *table = &vm_locked.vm->iommu_ptables[dma_device_id];

#if SECURE_WORLD == 1
	if (0 != (mode & MM_MODE_NS)) {
		table = &vm_locked.vm->arch.iommu_ptables_ns[dma_device_id];
	}
#endif

	mm_vm_identity_commit(table, begin, end, mode, ppool, ipa);
}

bool arch_vm_iommu_mm_identity_map(struct vm_locked vm_locked, paddr_t begin,
				   paddr_t end, uint32_t mode,
				   struct mpool *ppool, ipaddr_t *ipa,
				   uint8_t dma_device_id)
{
	/*
	 * No support to enforce access control through (stage 1) address
	 * translation for memory accesses by DMA device on behalf of an
	 * EL0/S-EL0 partition.
	 */
	if (vm_locked.vm->el0_partition) {
		return true;
	}

	if (dma_device_id >= vm_locked.vm->dma_device_count) {
		dlog_error("Illegal DMA device specified.\n");
		return false;
	}

	if (!arch_vm_iommu_mm_prepare(vm_locked, begin, end, mode, ppool,
				      dma_device_id)) {
		return false;
	}

	arch_vm_iommu_mm_commit(vm_locked, begin, end, mode, ppool, ipa,
				dma_device_id);

	return true;
}
