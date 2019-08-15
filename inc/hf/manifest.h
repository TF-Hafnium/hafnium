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

#include "hf/memiter.h"
#include "hf/spci.h"

/**
 * Holds information about one of the VMs described in the manifest.
 */
struct manifest_vm {
	/* Properties defined for both primary and secondary VMs. */
	struct memiter debug_name;

	/* Properties specific to secondary VMs. */
	struct {
		struct memiter kernel_filename;
		uint64_t mem_size;
		spci_vcpu_count_t vcpu_count;
	} secondary;
};

/**
 * Hafnium manifest parsed from FDT.
 */
struct manifest {
	spci_vm_count_t num_vms;
	struct manifest_vm vm[MAX_VMS];
};

enum manifest_return_code {
	MANIFEST_SUCCESS = 0,
	MANIFEST_ERROR_CORRUPTED_FDT,
	MANIFEST_ERROR_NO_ROOT_FDT_NODE,
	MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE,
	MANIFEST_ERROR_RESERVED_VM_ID,
	MANIFEST_ERROR_NO_PRIMARY_VM,
	MANIFEST_ERROR_TOO_MANY_VMS,
	MANIFEST_ERROR_PROPERTY_NOT_FOUND,
	MANIFEST_ERROR_MALFORMED_STRING,
	MANIFEST_ERROR_MALFORMED_INTEGER,
	MANIFEST_ERROR_INTEGER_OVERFLOW,
};

enum manifest_return_code manifest_init(struct manifest *manifest,
					struct memiter *fdt);

const char *manifest_strerror(enum manifest_return_code ret_code);
