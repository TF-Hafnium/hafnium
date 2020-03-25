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
#include "hf/dlog.h"
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

#define VM_ID_MAX (HF_VM_ID_OFFSET + MAX_VMS - 1)
#define VM_ID_MAX_DIGITS (5)
#define VM_NAME_EXTRA_CHARS (3) /* "vm" + number + '\0' */
#define VM_NAME_MAX_SIZE (VM_ID_MAX_DIGITS + VM_NAME_EXTRA_CHARS)
static_assert(VM_NAME_MAX_SIZE <= STRING_MAX_SIZE,
	      "VM name does not fit into a struct string.");
static_assert(VM_ID_MAX <= 99999, "Insufficient VM_NAME_BUF_SIZE");
static_assert(HF_TEE_VM_ID > VM_ID_MAX,
	      "TrustZone VM ID clashes with normal VM range.");

static inline size_t count_digits(spci_vm_id_t vm_id)
{
	size_t digits = 0;

	do {
		digits++;
		vm_id /= 10;
	} while (vm_id);
	return digits;
}

/**
 * Generates a string with the two letters "vm" followed by an integer.
 * Assumes `buf` is of size VM_NAME_BUF_SIZE.
 */
static void generate_vm_node_name(struct string *str, spci_vm_id_t vm_id)
{
	static const char *digits = "0123456789";
	size_t vm_id_digits = count_digits(vm_id);
	char *base = str->data;
	char *ptr = base + (VM_NAME_EXTRA_CHARS + vm_id_digits);

	CHECK(vm_id_digits <= VM_ID_MAX_DIGITS);
	*(--ptr) = '\0';
	do {
		*(--ptr) = digits[vm_id % 10];
		vm_id /= 10;
	} while (vm_id);
	*(--ptr) = 'm';
	*(--ptr) = 'v';
	CHECK(ptr == base);
}

/**
 * Read a boolean property: true if present; false if not. If present, the value
 * of the property must be empty else it is considered malformed.
 */
static enum manifest_return_code read_bool(const struct fdt_node *node,
					   const char *property, bool *out)
{
	struct memiter data;
	bool present = fdt_read_property(node, property, &data);

	if (present && memiter_size(&data) != 0) {
		return MANIFEST_ERROR_MALFORMED_BOOLEAN;
	}

	*out = present;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_string(const struct fdt_node *node,
					     const char *property,
					     struct string *out)
{
	struct memiter data;

	if (!fdt_read_property(node, property, &data)) {
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	switch (string_init(out, &data)) {
	case STRING_SUCCESS:
		return MANIFEST_SUCCESS;
	case STRING_ERROR_INVALID_INPUT:
		return MANIFEST_ERROR_MALFORMED_STRING;
	case STRING_ERROR_TOO_LONG:
		return MANIFEST_ERROR_STRING_TOO_LONG;
	}
}

static enum manifest_return_code read_optional_string(
	const struct fdt_node *node, const char *property, struct string *out)
{
	enum manifest_return_code ret;

	ret = read_string(node, property, out);
	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		string_init_empty(out);
		ret = MANIFEST_SUCCESS;
	}
	return ret;
}

static enum manifest_return_code read_uint64(const struct fdt_node *node,
					     const char *property,
					     uint64_t *out)
{
	struct memiter data;

	if (!fdt_read_property(node, property, &data)) {
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	if (!fdt_parse_number(&data, memiter_size(&data), out)) {
		return MANIFEST_ERROR_MALFORMED_INTEGER;
	}

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_optional_uint64(
	const struct fdt_node *node, const char *property,
	uint64_t default_value, uint64_t *out)
{
	enum manifest_return_code ret;

	ret = read_uint64(node, property, out);
	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		*out = default_value;
		return MANIFEST_SUCCESS;
	}
	return ret;
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

struct uint32list_iter {
	struct memiter mem_it;
};

static enum manifest_return_code read_optional_uint32list(
	const struct fdt_node *node, const char *property,
	struct uint32list_iter *out)
{
	struct memiter data;

	if (!fdt_read_property(node, property, &data)) {
		memiter_init(&out->mem_it, NULL, 0);
		return MANIFEST_SUCCESS;
	}

	if ((memiter_size(&data) % sizeof(uint32_t)) != 0) {
		return MANIFEST_ERROR_MALFORMED_INTEGER_LIST;
	}

	out->mem_it = data;
	return MANIFEST_SUCCESS;
}

static bool uint32list_has_next(const struct uint32list_iter *list)
{
	return memiter_size(&list->mem_it) > 0;
}

static enum manifest_return_code uint32list_get_next(
	struct uint32list_iter *list, uint32_t *out)
{
	uint64_t num;

	CHECK(uint32list_has_next(list));
	if (!fdt_parse_number(&list->mem_it, sizeof(uint32_t), &num)) {
		return MANIFEST_ERROR_MALFORMED_INTEGER;
	}

	*out = (uint32_t)num;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_vm(const struct fdt_node *node,
					  struct manifest_vm *vm,
					  spci_vm_id_t vm_id)
{
	struct uint32list_iter smcs;
	size_t idx;

	TRY(read_string(node, "debug_name", &vm->debug_name));
	TRY(read_optional_string(node, "kernel_filename",
				 &vm->kernel_filename));

	TRY(read_optional_uint32list(node, "smc_whitelist", &smcs));
	while (uint32list_has_next(&smcs) &&
	       vm->smc_whitelist.smc_count < MAX_SMCS) {
		idx = vm->smc_whitelist.smc_count++;
		TRY(uint32list_get_next(&smcs, &vm->smc_whitelist.smcs[idx]));
	}

	if (uint32list_has_next(&smcs)) {
		dlog_warning("%s SMC whitelist too long.\n", vm->debug_name);
	}

	TRY(read_bool(node, "smc_whitelist_permissive",
		      &vm->smc_whitelist.permissive));

	if (vm_id == HF_PRIMARY_VM_ID) {
		TRY(read_optional_string(node, "ramdisk_filename",
					 &vm->primary.ramdisk_filename));
		TRY(read_optional_uint64(node, "boot_address",
					 MANIFEST_INVALID_ADDRESS,
					 &vm->primary.boot_address));
	} else {
		TRY(read_uint64(node, "mem_size", &vm->secondary.mem_size));
		TRY(read_uint16(node, "vcpu_count", &vm->secondary.vcpu_count));
	}
	return MANIFEST_SUCCESS;
}

/**
 * Parse manifest from FDT.
 */
enum manifest_return_code manifest_init(struct manifest *manifest,
					struct memiter *manifest_fdt)
{
	struct string vm_name;
	struct fdt fdt;
	struct fdt_node hyp_node;
	size_t i = 0;
	bool found_primary_vm = false;

	memset_s(manifest, sizeof(*manifest), 0, sizeof(*manifest));

	if (!fdt_init_from_memiter(&fdt, manifest_fdt)) {
		return MANIFEST_ERROR_FILE_SIZE; /* TODO */
	}

	/* Find hypervisor node. */
	if (!fdt_find_node(&fdt, "/hypervisor", &hyp_node)) {
		return MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE;
	}

	/* Check "compatible" property. */
	if (!fdt_is_compatible(&hyp_node, "hafnium,hafnium")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	/* Iterate over reserved VM IDs and check no such nodes exist. */
	for (i = 0; i < HF_VM_ID_OFFSET; i++) {
		spci_vm_id_t vm_id = (spci_vm_id_t)i;
		struct fdt_node vm_node = hyp_node;

		generate_vm_node_name(&vm_name, vm_id);
		if (fdt_find_child(&vm_node, &vm_name)) {
			return MANIFEST_ERROR_RESERVED_VM_ID;
		}
	}

	/* Iterate over VM nodes until we find one that does not exist. */
	for (i = 0; i <= MAX_VMS; ++i) {
		spci_vm_id_t vm_id = HF_VM_ID_OFFSET + i;
		struct fdt_node vm_node = hyp_node;

		generate_vm_node_name(&vm_name, vm_id);
		if (!fdt_find_child(&vm_node, &vm_name)) {
			break;
		}

		if (i == MAX_VMS) {
			return MANIFEST_ERROR_TOO_MANY_VMS;
		}

		if (vm_id == HF_PRIMARY_VM_ID) {
			CHECK(found_primary_vm == false); /* sanity check */
			found_primary_vm = true;
		}

		manifest->vm_count = i + 1;
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
	case MANIFEST_ERROR_FILE_SIZE:
		return "Total size in header does not match file size";
	case MANIFEST_ERROR_NO_ROOT_NODE:
		return "Could not find root node in manifest";
	case MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE:
		return "Could not find \"hypervisor\" node in manifest";
	case MANIFEST_ERROR_NOT_COMPATIBLE:
		return "Hypervisor manifest entry not compatible with Hafnium";
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
	case MANIFEST_ERROR_STRING_TOO_LONG:
		return "String too long";
	case MANIFEST_ERROR_MALFORMED_INTEGER:
		return "Malformed integer property";
	case MANIFEST_ERROR_INTEGER_OVERFLOW:
		return "Integer overflow";
	case MANIFEST_ERROR_MALFORMED_INTEGER_LIST:
		return "Malformed integer list property";
	case MANIFEST_ERROR_MALFORMED_BOOLEAN:
		return "Malformed boolean property";
	}

	panic("Unexpected manifest return code.");
}
