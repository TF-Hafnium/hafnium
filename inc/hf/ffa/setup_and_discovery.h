/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/manifest.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

/** Returns the SPMC ID. */
struct ffa_value ffa_setup_spmc_id_get(void);

/**
 * Returns true if the FFA_SECONDARY_EP_REGISTER interface is supported at
 * the virtual FF-A instance.
 */
bool ffa_setup_is_secondary_ep_register_supported(void);

void ffa_setup_rxtx_map_spmc(paddr_t recv, paddr_t send, uint64_t page_count);

void ffa_setup_rxtx_map_forward(struct vm_locked vm_locked);

void ffa_setup_rxtx_unmap_forward(struct vm_locked vm_locked);

bool ffa_setup_partition_info_get_regs_forward_allowed(void);

size_t ffa_setup_partition_info_get_forward(
	const struct ffa_uuid *uuid, uint32_t flags,
	struct ffa_partition_info *partitions, size_t partitions_max_len,
	const size_t entries_count);

void ffa_setup_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
					paddr_t fdt_addr,
					size_t fdt_allocated_size,
					const struct manifest_vm *manifest_vm,
					const struct boot_params *boot_params);

/** Return the FF-A partition info VM/SP properties given the VM id. */
ffa_partition_properties_t ffa_setup_partition_properties(
	ffa_id_t caller_id, const struct vm *target);

bool ffa_setup_rx_release_forward(struct vm_locked vm_locked,
				  struct ffa_value *ret);

bool ffa_setup_acquire_receiver_rx(struct vm_locked to_locked,
				   struct ffa_value *ret);

bool ffa_ns_res_info_get_forward(struct vm_locked current_locked,
				 struct ffa_value args, struct ffa_value *ret);
