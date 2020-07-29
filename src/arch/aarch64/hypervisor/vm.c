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

		/*
		 * The PAuth mechanism holds state in the key registers. Only
		 * the primary VM is allowed to use the PAuth functionality for
		 * now. This prevents Hafnium from having to save/restore the
		 * key register on a VM switch.
		 */
		vm->arch.trapped_features |= HF_FEATURE_PAUTH;
	}
}

ffa_partition_properties_t arch_vm_partition_properties(ffa_vm_id_t id)
{
#if SECURE_WORLD == 0
	/*
	 * VMs supports indirect messaging.
	 * PVM supports sending direct messages.
	 * Secondary VMs support receiving direct messages.
	 */
	return FFA_PARTITION_INDIRECT_MSG | (id == HF_PRIMARY_VM_ID)
		       ? FFA_PARTITION_DIRECT_SEND
		       : FFA_PARTITION_DIRECT_RECV;
#else
	(void)id;

	/*
	 * SPs only support receiving direct messages.
	 */
	return FFA_PARTITION_DIRECT_RECV;
#endif
}
