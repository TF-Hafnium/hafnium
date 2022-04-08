/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/fdt.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/string.h"
#include "hf/vm.h"

#define MANIFEST_INVALID_ADDRESS UINT64_MAX
#define MANIFEST_INVALID_ID UINT32_MAX

#define SP_PKG_HEADER_MAGIC (0x474b5053)
#define SP_PKG_HEADER_VERSION (0x1)

#define SP_RTX_BUF_NAME_SIZE 10

#define SP_MAX_MEMORY_REGIONS 8
#define SP_MAX_DEVICE_REGIONS 8
#define SP_MAX_INTERRUPTS_PER_DEVICE 4
#define SP_MAX_STREAMS_PER_DEVICE 4

/** Mask for getting read/write/execute permission */
#define MM_PERM_MASK 0x7

/* Highest possible value for the boot-order field. */
#define DEFAULT_BOOT_ORDER 0xFFFF

enum run_time_el {
	EL1 = 0,
	S_EL0,
	S_EL1,
	SUPERVISOR_MODE,
	SECURE_USER_MODE,
	SECURE_SUPERVISOR_MODE
};

enum execution_state { AARCH64 = 0, AARCH32 };

enum xlat_granule { PAGE_4KB = 0, PAGE_16KB, PAGE_64KB };

/**
 * Partition Memory region as described in FFA v1.0 spec, Table 10
 */
struct memory_region {
	/**
	 * Specify PA, VA for S-EL0 partitions or IPA
	 * for S-EL1 partitions - optional.
	 */
	uintptr_t base_address;
	/** Page count - mandatory */
	uint32_t page_count;
	/** Memory attributes - mandatory */
	uint32_t attributes;
	/** Name of memory region - optional */
	struct string name;
};

struct interrupt {
	uint32_t id;
	uint32_t attributes;
};

/**
 * Partition Device region as described in FFA v1.0 spec, Table 11
 */
struct device_region {
	/** Device base PA - mandatory */
	uintptr_t base_address;
	/** Page count - mandatory */
	uint32_t page_count;
	/** Memory attributes - mandatory */
	uint32_t attributes;
	/** List of physical interrupt ID's and their attributes - optional */
	struct interrupt interrupts[SP_MAX_INTERRUPTS_PER_DEVICE];
	/** Count of physical interrupts - optional */
	uint8_t interrupt_count;
	/** SMMU ID - optional */
	uint32_t smmu_id;
	/** Count of Stream IDs assigned to device - optional */
	uint8_t stream_count;
	/** List of Stream IDs assigned to device - optional */
	uint32_t stream_ids[SP_MAX_STREAMS_PER_DEVICE];
	/** Exclusive access to an endpoint - optional */
	bool exclusive_access;
	/** Name of Device region - optional */
	struct string name;
};

/**
 * RX/TX buffer, reference to memory-region entries that describe RX/TX
 * buffers in partition manifest.
 */
struct rx_tx {
	bool available;
	uint32_t rx_phandle;
	uint32_t tx_phandle;
	struct memory_region *rx_buffer;
	struct memory_region *tx_buffer;
};

/**
 * Partition manifest as described in FF-A v1.0 spec section 3.1
 */
struct partition_manifest {
	/** FF-A expected version - mandatory */
	uint32_t ffa_version;
	/** UUID - mandatory */
	struct ffa_uuid uuid;
	/** Partition id - optional */
	ffa_vm_id_t id;
	/** Aux ids for mem transactions - optional */
	ffa_vm_id_t aux_id;

	/* NOTE: optional name field maps to VM debug_name field */

	/** mandatory */
	ffa_vcpu_count_t execution_ctx_count;
	/** EL1 or secure EL1, secure EL0 - mandatory */
	enum run_time_el run_time_el;
	/** AArch32 / AArch64 - mandatory */
	enum execution_state execution_state;
	/** optional */
	uintpaddr_t load_addr;
	/** optional */
	size_t ep_offset;
	/**  4/16/64KB - optional */
	enum xlat_granule xlat_granule;
	/** optional */
	uint16_t boot_order;

	/** Optional RX/TX buffers */
	struct rx_tx rxtx;

	/** mandatory - direct/indirect msg or both */
	uint8_t messaging_method;
	/** optional */
	bool managed_exit;
	/** optional - receipt of notifications. */
	bool notification_support;
	/** optional */
	bool has_primary_scheduler;
	/** optional - preemptible / run to completion */
	uint8_t runtime_model;
	/** optional - tuples SEPID/SMMUID/streamId */
	uint32_t stream_ep_ids[1];

	/** Memory regions */
	uint8_t mem_region_count;
	struct memory_region mem_regions[SP_MAX_MEMORY_REGIONS];
	/** Device regions */
	uint8_t dev_region_count;
	struct device_region dev_regions[SP_MAX_DEVICE_REGIONS];
};

/**
 *  Header for a FF-A partition package.
 */
struct sp_pkg_header {
	/** Magic used to identify a SP package. Value is "SPKG" */
	uint32_t magic;
	/** Version number of the header */
	uint32_t version;
	/** Offset in bytes to the partition manifest */
	uint32_t pm_offset;
	/** Size in bytes of the partition manifest */
	uint32_t pm_size;
	/** Offset in bytes to the base address of the partition binary */
	uint32_t img_offset;
	/** Size in bytes of the partition binary */
	uint32_t img_size;
};

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
	struct partition_manifest partition;

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
	MANIFEST_ERROR_MEMORY_REGION_NODE_EMPTY,
	MANIFEST_ERROR_DEVICE_REGION_NODE_EMPTY,
	MANIFEST_ERROR_RXTX_SIZE_MISMATCH,
	MANIFEST_ERROR_INVALID_MEM_PERM,
};

enum manifest_return_code manifest_init(struct mm_stage1_locked stage1_locked,
					struct manifest *manifest,
					struct memiter *manifest_fdt,
					struct mpool *ppool);

enum manifest_return_code parse_ffa_manifest(struct fdt *fdt,
					     struct manifest_vm *vm);
enum manifest_return_code sanity_check_ffa_manifest(struct manifest_vm *vm);
void manifest_dump(struct manifest_vm *vm);

const char *manifest_strerror(enum manifest_return_code ret_code);
