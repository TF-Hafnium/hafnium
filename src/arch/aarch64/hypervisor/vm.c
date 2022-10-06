/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm.h"

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

	if (vm->id != HF_PRIMARY_VM_ID) {
		/* Features to trap only for the secondary VMs. */

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
