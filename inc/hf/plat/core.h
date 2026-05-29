/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/boot_params.h"
#include "hf/manifest_helpers.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "vmapi/hf/ffa.h"

/**
 * Perform platform-specific boot time initialization.
 */
void plat_one_time_init(void);

/**
 * Set up any platform-specific mappings in the hypervisor's address space.
 * Returns true if the mappings were created successfully.
 */
bool plat_mm_init(struct mm_stage1_locked stage1_locked);

/**
 * Handle platform-specific paravirtual interfaces.
 * Returns true if the interface was handled by platform code, with return
 * values set for the next vCPU. Returns false if the interface is not handled
 * by platform code.
 */
bool plat_paravirt_interface_handler(struct ffa_value args, struct vcpu *vcpu,
				     struct vcpu **next);

/**
 * Parse platform-specific information from an FF-A manifest.
 * Returns MANIFEST_SUCCESS if the manifest was parsed succesfully, otherwise
 * the relevant manifest error code should be returned.
 */
enum manifest_return_code plat_parse_ffa_manifest(
	struct fdt *fdt, struct manifest_vm *vm,
	const struct boot_params *boot_params);

/**
 * Perform platform-specific loading of FF-A partition.
 * Returns true if the platform-specific components of the FF-A partition were
 * loaded successfully.
 */
bool plat_load_ffa_partition(struct mm_stage1_locked stage1_locked,
			     paddr_t mem_begin, paddr_t mem_end,
			     const struct manifest_vm *manifest_vm,
			     struct vm *current_vm);
