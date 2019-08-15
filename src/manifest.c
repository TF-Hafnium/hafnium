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

#include "hf/manifest.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/fdt.h"
#include "hf/static_assert.h"
#include "hf/std.h"

#define TRY(expr)                                            \
	do {                                                 \
		enum manifest_return_code ret_code = (expr); \
		if (ret_code != MANIFEST_SUCCESS) {          \
			return ret_code;                     \
		}                                            \
	} while (0)

#define VM_NAME_BUF_SIZE (2 + 5 + 1) /* "vm" + number + null terminator */
static_assert(MAX_VMS <= 99999, "Insufficient VM_NAME_BUF_SIZE");

/**
 * Generates a string with the two letters "vm" followed by an integer.
 * Assumes `buf` is of size VM_NAME_BUF_SIZE.
 */
static const char *generate_vm_node_name(char *buf, spci_vm_id_t vm_id)
{
	static const char *digits = "0123456789";
	char *ptr = buf + VM_NAME_BUF_SIZE;

	*(--ptr) = '\0';
	do {
		*(--ptr) = digits[vm_id % 10];
		vm_id /= 10;
	} while (vm_id);
	*(--ptr) = 'm';
	*(--ptr) = 'v';

	return ptr;
}

static enum manifest_return_code read_string(const struct fdt_node *node,
					     const char *property,
					     struct memiter *out)
{
	const char *data;
	uint32_t size;

	if (!fdt_read_property(node, property, &data, &size)) {
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	if (data[size - 1] != '\0') {
		return MANIFEST_ERROR_MALFORMED_STRING;
	}

	memiter_init(out, data, size - 1);
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_uint64(const struct fdt_node *node,
					     const char *property,
					     uint64_t *out)
{
	const char *data;
	uint32_t size;

	if (!fdt_read_property(node, property, &data, &size)) {
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	if (!fdt_parse_number(data, size, out)) {
		return MANIFEST_ERROR_MALFORMED_INTEGER;
	}

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_uint16(const struct fdt_node *node,
					     const char *property,
					     uint16_t *out)
{
	uint64_t value;

	TRY(read_uint64(node, property, &value));

	if (value > UINT16_MAX) {
		return MANIFEST_ERROR_INTEGER_OVERFLOW;
	}

	*out = (uint16_t)value;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_vm(struct fdt_node *node,
					  struct manifest_vm *vm,
					  spci_vm_id_t vm_id)
{
	TRY(read_string(node, "debug_name", &vm->debug_name));
	if (vm_id != HF_PRIMARY_VM_ID) {
		TRY(read_string(node, "kernel_filename",
				&vm->secondary.kernel_filename));
		TRY(read_uint64(node, "mem_size", &vm->secondary.mem_size));
		TRY(read_uint16(node, "vcpu_count", &vm->secondary.vcpu_count));
	}
	return MANIFEST_SUCCESS;
}

/**
 * Parse manifest from FDT.
 */
enum manifest_return_code manifest_init(struct manifest *manifest,
					struct memiter *fdt)
{
	char vm_name_buf[VM_NAME_BUF_SIZE];
	struct fdt_node hyp_node;
	size_t i = 0;
	bool found_primary_vm = false;

	memset_s(manifest, sizeof(*manifest), 0, sizeof(*manifest));

	/* Find hypervisor node. */
	if (!fdt_root_node(&hyp_node,
			   (const struct fdt_header *)memiter_base(fdt))) {
		return MANIFEST_ERROR_CORRUPTED_FDT;
	}
	if (!fdt_find_child(&hyp_node, "")) {
		return MANIFEST_ERROR_NO_ROOT_FDT_NODE;
	}
	if (!fdt_find_child(&hyp_node, "hypervisor")) {
		return MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE;
	}

	/* Iterate over reserved VM IDs and check no such nodes exist. */
	for (i = 0; i < HF_VM_ID_OFFSET; i++) {
		spci_vm_id_t vm_id = (spci_vm_id_t)i;
		struct fdt_node vm_node = hyp_node;
		const char *vm_name = generate_vm_node_name(vm_name_buf, vm_id);

		if (fdt_find_child(&vm_node, vm_name)) {
			return MANIFEST_ERROR_RESERVED_VM_ID;
		}
	}

	/* Iterate over VM nodes until we find one that does not exist. */
	for (i = 0; i <= MAX_VMS; ++i) {
		spci_vm_id_t vm_id = HF_VM_ID_OFFSET + i;
		struct fdt_node vm_node = hyp_node;
		const char *vm_name = generate_vm_node_name(vm_name_buf, vm_id);

		if (!fdt_find_child(&vm_node, vm_name)) {
			break;
		}

		if (i == MAX_VMS) {
			return MANIFEST_ERROR_TOO_MANY_VMS;
		}

		if (vm_id == HF_PRIMARY_VM_ID) {
			CHECK(found_primary_vm == false); /* sanity check */
			found_primary_vm = true;
		}

		manifest->num_vms = i + 1;
		TRY(parse_vm(&vm_node, &manifest->vm[i], vm_id));
	}

	if (!found_primary_vm) {
		return MANIFEST_ERROR_NO_PRIMARY_VM;
	}

	return MANIFEST_SUCCESS;
}

const char *manifest_strerror(enum manifest_return_code ret_code)
{
	switch (ret_code) {
	case MANIFEST_SUCCESS:
		return "Success";
	case MANIFEST_ERROR_CORRUPTED_FDT:
		return "Manifest failed FDT validation";
	case MANIFEST_ERROR_NO_ROOT_FDT_NODE:
		return "Could not find root node of manifest";
	case MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE:
		return "Could not find \"hypervisor\" node in manifest";
	case MANIFEST_ERROR_RESERVED_VM_ID:
		return "Manifest defines a VM with a reserved ID";
	case MANIFEST_ERROR_NO_PRIMARY_VM:
		return "Manifest does not contain a primary VM entry";
	case MANIFEST_ERROR_TOO_MANY_VMS:
		return "Manifest specifies more VMs than Hafnium has "
		       "statically allocated space for";
	case MANIFEST_ERROR_PROPERTY_NOT_FOUND:
		return "Property not found";
	case MANIFEST_ERROR_MALFORMED_STRING:
		return "Malformed string property";
	case MANIFEST_ERROR_MALFORMED_INTEGER:
		return "Malformed integer property";
	case MANIFEST_ERROR_INTEGER_OVERFLOW:
		return "Integer overflow";
	}

	panic("Unexpected manifest return code.");
}
