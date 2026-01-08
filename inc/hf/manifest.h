/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/boot_params.h"
#include "hf/fdt.h"
#include "hf/ffa.h"
#include "hf/ffa_partition_manifest.h"
#include "hf/manifest_return_codes.h"
#include "hf/memiter.h"
#include "hf/string.h"
#include "hf/vm.h"

/**
 * Holds information about one of the VMs described in the manifest.
 */
struct manifest_vm {
	/* Properties defined for both primary and secondary VMs. */
	struct string debug_name;
	struct string kernel_filename;
	struct smc_whitelist smc_whitelist;
	bool is_ffa_partition;
	bool is_hyp_loaded;
	struct ffa_partition_manifest partition;

	union {
		/* Properties specific to the primary VM. */
		struct {
			uint64_t boot_address;
			struct string ramdisk_filename;
		} primary;
		/* Properties specific to secondary VMs. */
		struct {
			uint64_t mem_size;
			ffa_vcpu_count_t vcpu_count;
			struct string fdt_filename;
		} secondary;
	};
};

/**
 * Hafnium manifest parsed from FDT.
 */
struct manifest {
	bool ffa_tee_enabled;
	ffa_vm_count_t vm_count;
	struct manifest_vm vm[MAX_VMS];
};

enum manifest_return_code manifest_init(struct mm_stage1_locked stage1_locked,
					struct manifest **manifest_ret,
					struct memiter *manifest_fdt,
					struct boot_params *boot_params);
enum manifest_return_code parse_ffa_manifest(
	struct fdt *fdt, struct manifest_vm *vm,
	struct fdt_node *boot_info_node, const struct boot_params *boot_params);

void manifest_dump(struct manifest_vm *vm);

const char *manifest_strerror(enum manifest_return_code ret_code);
