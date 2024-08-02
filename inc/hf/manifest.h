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

enum manifest_return_code {
	MANIFEST_SUCCESS = 0,
	MANIFEST_ERROR_FILE_SIZE,
	MANIFEST_ERROR_MALFORMED_DTB,
	MANIFEST_ERROR_NO_ROOT_NODE,
	MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE,
	MANIFEST_ERROR_NOT_COMPATIBLE,
	MANIFEST_ERROR_RESERVED_VM_ID,
	MANIFEST_ERROR_NO_PRIMARY_VM,
	MANIFEST_ERROR_TOO_MANY_VMS,
	MANIFEST_ERROR_PROPERTY_NOT_FOUND,
	MANIFEST_ERROR_MALFORMED_STRING,
	MANIFEST_ERROR_STRING_TOO_LONG,
	MANIFEST_ERROR_MALFORMED_INTEGER,
	MANIFEST_ERROR_INTEGER_OVERFLOW,
	MANIFEST_ERROR_MALFORMED_INTEGER_LIST,
	MANIFEST_ERROR_MALFORMED_BOOLEAN,
	MANIFEST_ERROR_ARGUMENTS_LIST_EMPTY,
	MANIFEST_ERROR_MEMORY_REGION_NODE_EMPTY,
	MANIFEST_ERROR_DEVICE_REGION_NODE_EMPTY,
	MANIFEST_ERROR_RXTX_SIZE_MISMATCH,
	MANIFEST_ERROR_MEM_REGION_EMPTY,
	MANIFEST_ERROR_MEM_REGION_UNALIGNED,
	MANIFEST_ERROR_BASE_ADDRESS_AND_RELATIVE_ADDRESS,
	MANIFEST_ERROR_MEM_REGION_OVERLAP,
	MANIFEST_ERROR_MEMORY_MISSING,
	MANIFEST_ERROR_MEM_REGION_INVALID,
	MANIFEST_ERROR_DEVICE_MEM_REGION_INVALID,
	MANIFEST_ERROR_PARTITION_ADDRESS_OVERLAP,
	MANIFEST_ERROR_INVALID_MEM_PERM,
	MANIFEST_ERROR_INTERRUPT_ID_REPEATED,
	MANIFEST_ERROR_ILLEGAL_NS_INT_ACTION,
	MANIFEST_ERROR_INTERRUPT_ID_NOT_IN_LIST,
	MANIFEST_ERROR_ILLEGAL_OTHER_S_INT_ACTION,
	MANIFEST_ERROR_INVALID_BOOT_ORDER,
	MANIFEST_ERROR_UUID_ALL_ZEROS,
	MANIFEST_ERROR_TOO_MANY_UUIDS,
	MANIFEST_ERROR_MISSING_SMMU_ID,
	MANIFEST_ERROR_MISMATCH_DMA_ACCESS_PERMISSIONS,
	MANIFEST_ERROR_STREAM_IDS_OVERFLOW,
	MANIFEST_ERROR_DMA_ACCESS_PERMISSIONS_OVERFLOW,
	MANIFEST_ERROR_DMA_DEVICE_OVERFLOW,
	MANIFEST_ERROR_VM_AVAILABILITY_MESSAGE_INVALID,
};

enum manifest_return_code manifest_init(struct mm_stage1_locked stage1_locked,
					struct manifest **manifest_ret,
					struct memiter *manifest_fdt,
					struct boot_params *boot_params,
					struct mpool *ppool);
void manifest_deinit(struct mpool *ppool);
enum manifest_return_code parse_ffa_manifest(
	struct fdt *fdt, struct manifest_vm *vm,
	struct fdt_node *boot_info_node, const struct boot_params *boot_params);

void manifest_dump(struct manifest_vm *vm);

const char *manifest_strerror(enum manifest_return_code ret_code);
