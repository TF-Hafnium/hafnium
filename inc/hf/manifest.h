/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "hf/addr.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/string.h"
#include "hf/vm.h"

#define MANIFEST_INVALID_ADDRESS UINT64_MAX

#define SP_PKG_HEADER_MAGIC (0x474b5053)
#define SP_PKG_HEADER_VERSION (0x1)

#define SP_RTX_BUF_NAME_SIZE 10

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

enum messaging_method {
	DIRECT_MESSAGING = 0,
	INDIRECT_MESSAGING,
	BOTH_MESSAGING
};

/**
 * Partition manifest as described in PSA FF-A v1.0 spec section 3.1
 */
struct sp_manifest {
	/** PSA-FF-A expected version - mandatory */
	uint32_t ffa_version;
	/** UUID - mandatory */
	uint32_t uuid[4];
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
	/**  4/16/64KB - mandatory */
	enum xlat_granule xlat_granule;
	/** optional */
	uint16_t boot_order;

	/** Optional RX/TX buffers */
	struct {
		bool rxtx_found;
		/** optional */
		uint64_t base_address;
		/** optional */
		uint16_t pages_count;
		/** mandatory */
		uint16_t attributes;
		/** Optional */
		char name[SP_RTX_BUF_NAME_SIZE];
	} rxtx;

	/** mandatory - direct/indirect msg or both */
	enum messaging_method messaging_method;
	/** optional */
	bool has_primary_scheduler;
	/** optional - preemptible / run to completion */
	uint8_t runtime_model;
	/** optional */
	bool time_slice_mem;
	/** optional - tuples SEPID/SMMUID/streamId */
	uint32_t stream_ep_ids[1];
};

/**
 *  Header for a PSA FF-A partition package.
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
	struct sp_manifest sp;

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
};

enum manifest_return_code manifest_init(struct mm_stage1_locked stage1_locked,
					struct manifest *manifest,
					struct memiter *manifest_fdt,
					struct mpool *ppool);

void manifest_dump(struct manifest_vm *vm);

const char *manifest_strerror(enum manifest_return_code ret_code);
