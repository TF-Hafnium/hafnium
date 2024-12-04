/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/setup_and_discovery.h"

#include "hf/check.h"
#include "hf/manifest.h"
#include "hf/vm.h"

#include "smc.h"

struct ffa_value ffa_setup_spmc_id_get(void)
{
	/*
	 * Since we are running in the SPMC use FFA_ID_GET to fetch our
	 * ID from the SPMD.
	 */
	return smc_ffa_call((struct ffa_value){.func = FFA_ID_GET_32});
}

/**
 * Returns FFA_SUCCESS as FFA_SECONDARY_EP_REGISTER is supported at the
 * secure virtual FF-A instance.
 */
bool ffa_setup_is_secondary_ep_register_supported(void)
{
	return true;
}

void ffa_setup_rxtx_map_forward(struct vm_locked vm_locked)
{
	(void)vm_locked;
}

void ffa_setup_rxtx_unmap_forward(struct vm_locked vm_locked)
{
	(void)vm_locked;
}

bool ffa_setup_partition_info_get_regs_forward_allowed(void)
{
	/*
	 * Allow forwarding from the SPMC to SPMD unconditionally.
	 */
	return true;
}

/** Forward helper for FFA_PARTITION_INFO_GET. */
ffa_vm_count_t ffa_setup_partition_info_get_forward(
	const struct ffa_uuid *uuid, uint32_t flags,
	struct ffa_partition_info *partitions, ffa_vm_count_t vm_count)
{
	/* The SPMC does not forward FFA_PARTITION_INFO_GET. */

	(void)uuid;
	(void)flags;
	(void)partitions;

	return vm_count;
}

void ffa_setup_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
					paddr_t fdt_addr,
					size_t fdt_allocated_size,
					const struct manifest_vm *manifest_vm,
					const struct boot_params *boot_params,
					struct mpool *ppool)
{
	(void)boot_params;
	(void)stage1_locked;
	(void)fdt_addr;
	(void)fdt_allocated_size;
	(void)manifest_vm;
	(void)ppool;
	/* should never be called in SPMC */
	CHECK(false);
}

ffa_partition_properties_t ffa_setup_partition_properties(
	ffa_id_t caller_id, const struct vm *target)
{
	ffa_partition_properties_t result = target->messaging_method;
	bool is_ffa_version_ge_v1_2 = (target->ffa_version >= FFA_VERSION_1_2);
	ffa_partition_properties_t final_mask;
	ffa_partition_properties_t dir_msg_mask = FFA_PARTITION_DIRECT_REQ_RECV;
	ffa_partition_properties_t dir_msg2_mask =
		FFA_PARTITION_DIRECT_REQ2_RECV;

	/*
	 * SPs support full direct messaging communication with other SPs,
	 * and are allowed to only receive direct requests from the other world.
	 * SPs cannot send direct requests to the other world.
	 *
	 * If caller is an SP, advertise that target can send messages.
	 * If caller is a VM, advertise that target can't send messages.
	 */
	if (vm_id_is_current_world(caller_id)) {
		dir_msg_mask |= FFA_PARTITION_DIRECT_REQ_SEND;
		dir_msg2_mask |= FFA_PARTITION_DIRECT_REQ2_SEND;
	}

	/* Consider dir_msg2_mask if FFA_VERSION is 1.2 or above. */
	final_mask = is_ffa_version_ge_v1_2 ? (dir_msg2_mask | dir_msg_mask)
					    : dir_msg_mask;

	return result & final_mask;
}

bool ffa_setup_rx_release_forward(struct vm_locked vm_locked,
				  struct ffa_value *ret)
{
	(void)vm_locked;
	(void)ret;

	return false;
}

bool ffa_setup_acquire_receiver_rx(struct vm_locked to_locked,
				   struct ffa_value *ret)
{
	(void)to_locked;
	(void)ret;

	return true;
}
