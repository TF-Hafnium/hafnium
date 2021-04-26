/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/vm.h"

#include "smc.h"

struct ffa_value plat_ffa_spmc_id_get(void)
{
	/* Fetch the SPMC ID from the SPMD using FFA_SPM_ID_GET. */
	return smc_ffa_call((struct ffa_value){.func = FFA_SPM_ID_GET_32});
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t vm_id, const struct vm *target)
{
	ffa_partition_properties_t result =
		target->messaging_method | ~FFA_PARTITION_MANAGED_EXIT;
	/*
	 * VMs support indirect messaging only in the Normal World.
	 * Primary VM cannot receive direct requests.
	 * Secondary VMs cannot send direct requests.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		result &= ~FFA_PARTITION_INDIRECT_MSG;
	}
	if (target->id == HF_PRIMARY_VM_ID) {
		result &= ~FFA_PARTITION_DIRECT_REQ_RECV;
	} else {
		result &= ~FFA_PARTITION_DIRECT_REQ_SEND;
	}
	return result;
}
