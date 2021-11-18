/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/other_world.h"

#include "hf/arch/mmu.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "smc.h"

bool arch_other_world_vm_init(struct vm *other_world_vm, struct mpool *ppool)
{
	struct vm_locked other_world_vm_locked;
	bool ret = false;

	/* Map 1TB address range to "Other world VM" Stage-2 */
	other_world_vm_locked = vm_lock(other_world_vm);

	if (!vm_identity_map(other_world_vm_locked, pa_init(0),
			     pa_init(UINT64_C(1024) * 1024 * 1024 * 1024),
			     MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS,
			     ppool, NULL)) {
		dlog_error(
			"Unable to initialise address space for "
			"Hypervisor VM.\n");
		goto out;
	}

	/* Enabling all communication methods for the other world. */
	other_world_vm->messaging_method =
		FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_DIRECT_REQ_SEND;

	ret = true;

out:
	vm_unlock(&other_world_vm_locked);

	return ret;
}

struct ffa_value arch_other_world_call(struct ffa_value args)
{
	return smc_ffa_call(args);
}
