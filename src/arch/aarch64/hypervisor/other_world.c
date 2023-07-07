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

bool arch_other_world_vm_init(struct vm *other_world_vm,
			      const struct boot_params *params,
			      struct mpool *ppool)
{
	const char *err_msg =
		"Unable to initialise address space for Other world VM.\n";
	struct vm_locked other_world_vm_locked;
	bool ret = false;
	uint32_t i;

	other_world_vm_locked = vm_lock(other_world_vm);

	/* Enabling all communication methods for the other world. */
	other_world_vm->messaging_method =
		FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_DIRECT_REQ_SEND;

	/* Map NS mem ranges to "Other world VM" Stage-2 PTs. */
	for (i = 0; i < params->ns_mem_ranges_count; i++) {
		if (!vm_identity_map(
			    other_world_vm_locked,
			    params->ns_mem_ranges[i].begin,
			    params->ns_mem_ranges[i].end,
			    MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_NS,
			    ppool, NULL)) {
			dlog_error("%s", err_msg);
			goto out;
		}
	}
	/*
	 * Force the hypervisor's version to be same as ours.
	 * FF-A version at hypervisor's initialization is not getting to the
	 * SPMC.
	 * TODO: fix the described above and delete this.
	 */
	other_world_vm->ffa_version = FFA_VERSION_COMPILED;

	ret = true;

out:
	vm_unlock(&other_world_vm_locked);

	return ret;
}

struct ffa_value arch_other_world_call(struct ffa_value args)
{
	return smc_ffa_call(args);
}

struct ffa_value arch_other_world_call_ext(struct ffa_value args)
{
	return smc_ffa_call_ext(args);
}
