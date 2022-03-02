/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/manifest.h"

#include "hf/addr.h"
#include "hf/assert.h"
#include "hf/check.h"
#include "hf/dlog.h"
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
static_assert((HF_OTHER_WORLD_ID > VM_ID_MAX) ||
		      (HF_OTHER_WORLD_ID < HF_VM_ID_BASE),
	      "TrustZone VM ID clashes with normal VM range.");

static inline size_t count_digits(ffa_vm_id_t vm_id)
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
static void generate_vm_node_name(struct string *str, ffa_vm_id_t vm_id)
{
	static const char *digits = "0123456789";
	size_t vm_id_digits = count_digits(vm_id);
	char *base = str->data;
	char *ptr = base + (VM_NAME_EXTRA_CHARS + vm_id_digits);

	assert(vm_id_digits <= VM_ID_MAX_DIGITS);
	*(--ptr) = '\0';
	do {
		*(--ptr) = digits[vm_id % 10];
		vm_id /= 10;
	} while (vm_id);
	*(--ptr) = 'm';
	*(--ptr) = 'v';
	assert(ptr == base);
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

static enum manifest_return_code read_uint32(const struct fdt_node *node,
					     const char *property,
					     uint32_t *out)
{
	uint64_t value;

	TRY(read_uint64(node, property, &value));

	if (value > UINT32_MAX) {
		return MANIFEST_ERROR_INTEGER_OVERFLOW;
	}

	*out = (uint32_t)value;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_optional_uint32(
	const struct fdt_node *node, const char *property,
	uint32_t default_value, uint32_t *out)
{
	enum manifest_return_code ret;

	ret = read_uint32(node, property, out);
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

static enum manifest_return_code read_optional_uint16(
	const struct fdt_node *node, const char *property,
	uint16_t default_value, uint16_t *out)
{
	enum manifest_return_code ret;

	ret = read_uint16(node, property, out);
	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		*out = default_value;
		return MANIFEST_SUCCESS;
	}

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_uint8(const struct fdt_node *node,
					    const char *property, uint8_t *out)
{
	uint64_t value;

	TRY(read_uint64(node, property, &value));

	if (value > UINT8_MAX) {
		return MANIFEST_ERROR_INTEGER_OVERFLOW;
	}

	*out = (uint8_t)value;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_optional_uint8(
	const struct fdt_node *node, const char *property,
	uint8_t default_value, uint8_t *out)
{
	enum manifest_return_code ret;

	ret = read_uint8(node, property, out);
	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		*out = default_value;
		return MANIFEST_SUCCESS;
	}

	return MANIFEST_SUCCESS;
}

struct uint32list_iter {
	struct memiter mem_it;
};

static enum manifest_return_code read_uint32list(const struct fdt_node *node,
						 const char *property,
						 struct uint32list_iter *out)
{
	struct memiter data;

	if (!fdt_read_property(node, property, &data)) {
		memiter_init(&out->mem_it, NULL, 0);
		return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
	}

	if ((memiter_size(&data) % sizeof(uint32_t)) != 0) {
		return MANIFEST_ERROR_MALFORMED_INTEGER_LIST;
	}

	out->mem_it = data;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code read_optional_uint32list(
	const struct fdt_node *node, const char *property,
	struct uint32list_iter *out)
{
	enum manifest_return_code ret = read_uint32list(node, property, out);

	if (ret == MANIFEST_ERROR_PROPERTY_NOT_FOUND) {
		return MANIFEST_SUCCESS;
	}
	return ret;
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

static enum manifest_return_code parse_vm_common(const struct fdt_node *node,
						 struct manifest_vm *vm,
						 ffa_vm_id_t vm_id)
{
	struct uint32list_iter smcs;
	size_t idx;

	TRY(read_bool(node, "is_ffa_partition", &vm->is_ffa_partition));

	TRY(read_bool(node, "hyp_loaded", &vm->is_hyp_loaded));

	TRY(read_string(node, "debug_name", &vm->debug_name));

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

	if (vm_id != HF_PRIMARY_VM_ID) {
		TRY(read_uint64(node, "mem_size", &vm->secondary.mem_size));
		TRY(read_uint16(node, "vcpu_count", &vm->secondary.vcpu_count));
		TRY(read_optional_string(node, "fdt_filename",
					 &vm->secondary.fdt_filename));
	}

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_vm(struct fdt_node *node,
					  struct manifest_vm *vm,
					  ffa_vm_id_t vm_id)
{
	TRY(read_optional_string(node, "kernel_filename",
				 &vm->kernel_filename));

	if (vm_id == HF_PRIMARY_VM_ID) {
		TRY(read_optional_string(node, "ramdisk_filename",
					 &vm->primary.ramdisk_filename));
		TRY(read_optional_uint64(node, "boot_address",
					 MANIFEST_INVALID_ADDRESS,
					 &vm->primary.boot_address));
	}
	TRY(read_optional_uint8(node, "exception-level", (uint8_t)EL1,
				(uint8_t *)&vm->partition.run_time_el));

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_ffa_memory_region_node(
	struct fdt_node *mem_node, struct memory_region *mem_regions,
	uint8_t *count, struct rx_tx *rxtx)
{
	uint32_t phandle;
	uint8_t i = 0;

	dlog_verbose("  Partition memory regions\n");

	if (!fdt_is_compatible(mem_node, "arm,ffa-manifest-memory-regions")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (!fdt_first_child(mem_node)) {
		return MANIFEST_ERROR_MEMORY_REGION_NODE_EMPTY;
	}

	do {
		dlog_verbose("    Memory Region[%u]\n", i);

		TRY(read_optional_string(mem_node, "description",
					 &mem_regions[i].name));
		dlog_verbose("      Name: %s\n",
			     string_data(&mem_regions[i].name));

		TRY(read_optional_uint64(mem_node, "base-address",
					 MANIFEST_INVALID_ADDRESS,
					 &mem_regions[i].base_address));
		dlog_verbose("      Base address:  %#x\n",
			     mem_regions[i].base_address);

		TRY(read_uint32(mem_node, "pages-count",
				&mem_regions[i].page_count));
		dlog_verbose("      Pages_count:  %u\n",
			     mem_regions[i].page_count);

		TRY(read_uint32(mem_node, "attributes",
				&mem_regions[i].attributes));
		mem_regions[i].attributes &= MM_PERM_MASK;

		if (mem_regions[i].attributes != (MM_MODE_R) &&
		    mem_regions[i].attributes != (MM_MODE_R | MM_MODE_W) &&
		    mem_regions[i].attributes != (MM_MODE_R | MM_MODE_X)) {
			return MANIFEST_ERROR_INVALID_MEM_PERM;
		}

		dlog_verbose("      Attributes:  %u\n",
			     mem_regions[i].attributes);

		if (rxtx->available) {
			TRY(read_optional_uint32(
				mem_node, "phandle",
				(uint32_t)MANIFEST_INVALID_ADDRESS, &phandle));
			if (phandle == rxtx->rx_phandle) {
				dlog_verbose("      Assigned as RX buffer\n");
				rxtx->rx_buffer = &mem_regions[i];
			} else if (phandle == rxtx->tx_phandle) {
				dlog_verbose("      Assigned as TX buffer\n");
				rxtx->tx_buffer = &mem_regions[i];
			}
		}

		i++;
	} while (fdt_next_sibling(mem_node) && (i < SP_MAX_MEMORY_REGIONS));

	if (rxtx->available &&
	    (rxtx->rx_buffer->page_count != rxtx->tx_buffer->page_count)) {
		return MANIFEST_ERROR_RXTX_SIZE_MISMATCH;
	}

	*count = i;

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_ffa_device_region_node(
	struct fdt_node *dev_node, struct device_region *dev_regions,
	uint8_t *count)
{
	struct uint32list_iter list;
	uint8_t i = 0;
	uint32_t j = 0;

	dlog_verbose("  Partition Device Regions\n");

	if (!fdt_is_compatible(dev_node, "arm,ffa-manifest-device-regions")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (!fdt_first_child(dev_node)) {
		return MANIFEST_ERROR_DEVICE_REGION_NODE_EMPTY;
	}

	do {
		dlog_verbose("    Device Region[%u]\n", i);

		TRY(read_optional_string(dev_node, "description",
					 &dev_regions[i].name));
		dlog_verbose("      Name: %s\n",
			     string_data(&dev_regions[i].name));

		TRY(read_uint64(dev_node, "base-address",
				&dev_regions[i].base_address));
		dlog_verbose("      Base address:  %#x\n",
			     dev_regions[i].base_address);

		TRY(read_uint32(dev_node, "pages-count",
				&dev_regions[i].page_count));
		dlog_verbose("      Pages_count:  %u\n",
			     dev_regions[i].page_count);

		TRY(read_uint32(dev_node, "attributes",
				&dev_regions[i].attributes));
		dev_regions[i].attributes =
			(dev_regions[i].attributes & MM_PERM_MASK) | MM_MODE_D;

		if (dev_regions[i].attributes != (MM_MODE_R | MM_MODE_D) &&
		    dev_regions[i].attributes !=
			    (MM_MODE_R | MM_MODE_W | MM_MODE_D)) {
			return MANIFEST_ERROR_INVALID_MEM_PERM;
		}

		dlog_verbose("      Attributes:  %u\n",
			     dev_regions[i].attributes);

		TRY(read_optional_uint32list(dev_node, "interrupts", &list));
		dlog_verbose("      Interrupt List:\n");
		j = 0;
		while (uint32list_has_next(&list) &&
		       j < SP_MAX_INTERRUPTS_PER_DEVICE) {
			TRY(uint32list_get_next(
				&list, &dev_regions[i].interrupts[j].id));
			if (uint32list_has_next(&list)) {
				TRY(uint32list_get_next(&list,
							&dev_regions[i]
								 .interrupts[j]
								 .attributes));
			} else {
				return MANIFEST_ERROR_MALFORMED_INTEGER_LIST;
			}

			dlog_verbose("        ID = %u, attributes = %u\n",
				     dev_regions[i].interrupts[j].id,
				     dev_regions[i].interrupts[j].attributes);
			j++;
		}

		dev_regions[i].interrupt_count = j;
		if (j == 0) {
			dlog_verbose("        Empty\n");
		}

		TRY(read_optional_uint32(dev_node, "smmu-id",
					 MANIFEST_INVALID_ID,
					 &dev_regions[i].smmu_id));
		if (dev_regions[i].smmu_id != MANIFEST_INVALID_ID) {
			dlog_verbose("      smmu-id:  %u\n",
				     dev_regions[i].smmu_id);
		}

		TRY(read_optional_uint32list(dev_node, "stream-ids", &list));
		dlog_verbose("      Stream IDs assigned:\n");

		j = 0;
		while (uint32list_has_next(&list) &&
		       j < SP_MAX_STREAMS_PER_DEVICE) {
			TRY(uint32list_get_next(&list,
						&dev_regions[i].stream_ids[j]));
			dlog_verbose("        %u\n",
				     dev_regions[i].stream_ids[j]);
			j++;
		}
		if (j == 0) {
			dlog_verbose("        None\n");
		}
		dev_regions[i].stream_count = j;

		TRY(read_bool(dev_node, "exclusive-access",
			      &dev_regions[i].exclusive_access));
		dlog_verbose("      Exclusive_access: %u\n",
			     dev_regions[i].exclusive_access);

		i++;
	} while (fdt_next_sibling(dev_node) && (i < SP_MAX_DEVICE_REGIONS));

	*count = i;

	return MANIFEST_SUCCESS;
}

enum manifest_return_code parse_ffa_manifest(struct fdt *fdt,
					     struct manifest_vm *vm)
{
	unsigned int i = 0;
	struct uint32list_iter uuid;
	uint32_t uuid_word;
	struct fdt_node root;
	struct fdt_node ffa_node;
	struct string rxtx_node_name = STRING_INIT("rx_tx-info");
	struct string mem_region_node_name = STRING_INIT("memory-regions");
	struct string dev_region_node_name = STRING_INIT("device-regions");

	if (!fdt_find_node(fdt, "/", &root)) {
		return MANIFEST_ERROR_NO_ROOT_NODE;
	}

	/* Check "compatible" property. */
	if (!fdt_is_compatible(&root, "arm,ffa-manifest-1.0")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	TRY(read_uint32(&root, "ffa-version", &vm->partition.ffa_version));
	dlog_verbose("  Expected FF-A version %u.%u\n",
		     vm->partition.ffa_version >> 16,
		     vm->partition.ffa_version & 0xffff);

	TRY(read_uint32list(&root, "uuid", &uuid));

	while (uint32list_has_next(&uuid) && i < 4) {
		TRY(uint32list_get_next(&uuid, &uuid_word));
		vm->partition.uuid.uuid[i] = uuid_word;
		i++;
	}
	dlog_verbose("  UUID %#x-%x-%x-%x\n", vm->partition.uuid.uuid[0],
		     vm->partition.uuid.uuid[1], vm->partition.uuid.uuid[2],
		     vm->partition.uuid.uuid[3]);

	TRY(read_uint16(&root, "execution-ctx-count",
			&vm->partition.execution_ctx_count));
	dlog_verbose("  Number of execution context %u\n",
		     vm->partition.execution_ctx_count);

	TRY(read_uint8(&root, "exception-level",
		       (uint8_t *)&vm->partition.run_time_el));
	dlog_verbose("  Run-time EL %u\n", vm->partition.run_time_el);

	TRY(read_uint8(&root, "execution-state",
		       (uint8_t *)&vm->partition.execution_state));
	dlog_verbose("  Execution state %u\n", vm->partition.execution_state);

	TRY(read_optional_uint64(&root, "load-address", 0,
				 &vm->partition.load_addr));
	dlog_verbose("  Load address %#x\n", vm->partition.load_addr);

	TRY(read_optional_uint64(&root, "entrypoint-offset", 0,
				 &vm->partition.ep_offset));
	dlog_verbose("  Entry point offset %#x\n", vm->partition.ep_offset);

	TRY(read_optional_uint16(&root, "boot-order", DEFAULT_BOOT_ORDER,
				 &vm->partition.boot_order));
	dlog_verbose("  Boot order %#u\n", vm->partition.boot_order);

	TRY(read_optional_uint8(&root, "xlat-granule", 0,
				(uint8_t *)&vm->partition.xlat_granule));
	dlog_verbose("  Translation granule %u\n", vm->partition.xlat_granule);

	ffa_node = root;
	if (fdt_find_child(&ffa_node, &rxtx_node_name)) {
		if (!fdt_is_compatible(&ffa_node,
				       "arm,ffa-manifest-rx_tx-buffer")) {
			return MANIFEST_ERROR_NOT_COMPATIBLE;
		}

		/*
		 * Read only phandles for now, it will be used to update buffers
		 * while parsing memory regions.
		 */
		TRY(read_uint32(&ffa_node, "rx-buffer",
				&vm->partition.rxtx.rx_phandle));

		TRY(read_uint32(&ffa_node, "tx-buffer",
				&vm->partition.rxtx.tx_phandle));

		vm->partition.rxtx.available = true;
	}

	TRY(read_uint8(&root, "messaging-method",
		       (uint8_t *)&vm->partition.messaging_method));
	dlog_verbose("  Messaging method %u\n", vm->partition.messaging_method);

	TRY(read_bool(&root, "managed-exit", &vm->partition.managed_exit));
	if (vm->partition.managed_exit) {
		dlog_verbose("  Managed Exit Supported\n");
	}

	TRY(read_bool(&root, "notification-support",
		      &vm->partition.notification_support));
	if (vm->partition.notification_support) {
		dlog_verbose("  Notifications Receipt Supported\n");
	}

	/* Parse memory-regions */
	ffa_node = root;
	if (fdt_find_child(&ffa_node, &mem_region_node_name)) {
		TRY(parse_ffa_memory_region_node(
			&ffa_node, vm->partition.mem_regions,
			&vm->partition.mem_region_count, &vm->partition.rxtx));
	}
	dlog_verbose("  Total %u memory regions found\n",
		     vm->partition.mem_region_count);

	/* Parse Device-regions */
	ffa_node = root;
	if (fdt_find_child(&ffa_node, &dev_region_node_name)) {
		TRY(parse_ffa_device_region_node(
			&ffa_node, vm->partition.dev_regions,
			&vm->partition.dev_region_count));
	}
	dlog_verbose("  Total %u device regions found\n",
		     vm->partition.dev_region_count);

	return sanity_check_ffa_manifest(vm);
}

enum manifest_return_code sanity_check_ffa_manifest(struct manifest_vm *vm)
{
	uint16_t ffa_version_major;
	uint16_t ffa_version_minor;
	enum manifest_return_code ret_code = MANIFEST_SUCCESS;
	const char *error_string = "specified in manifest is unsupported";
	uint32_t k = 0;

	/* ensure that the SPM version is compatible */
	ffa_version_major = (vm->partition.ffa_version & 0xffff0000) >>
			    FFA_VERSION_MAJOR_OFFSET;
	ffa_version_minor = vm->partition.ffa_version & 0xffff;

	if (ffa_version_major != FFA_VERSION_MAJOR ||
	    ffa_version_minor > FFA_VERSION_MINOR) {
		dlog_error("FF-A partition manifest version %s: %u.%u\n",
			   error_string, ffa_version_major, ffa_version_minor);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (vm->partition.xlat_granule != PAGE_4KB) {
		dlog_error("Translation granule %s: %u\n", error_string,
			   vm->partition.xlat_granule);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (vm->partition.execution_state != AARCH64) {
		dlog_error("Execution state %s: %u\n", error_string,
			   vm->partition.execution_state);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (vm->partition.run_time_el != EL1 &&
	    vm->partition.run_time_el != S_EL1 &&
	    vm->partition.run_time_el != S_EL0) {
		dlog_error("Exception level %s: %d\n", error_string,
			   vm->partition.run_time_el);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if ((vm->partition.messaging_method &
	     ~(FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_DIRECT_REQ_SEND |
	       FFA_PARTITION_INDIRECT_MSG)) != 0U) {
		dlog_error("Messaging method %s: %x\n", error_string,
			   vm->partition.messaging_method);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (vm->partition.run_time_el == S_EL0 &&
	    vm->partition.execution_ctx_count != 1) {
		dlog_error(
			"Exception level and execution context count %s: %d "
			"%d\n",
			error_string, vm->partition.run_time_el,
			vm->partition.execution_ctx_count);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	for (uint8_t i = 0; i < vm->partition.dev_region_count; i++) {
		struct device_region dev_region;

		dev_region = vm->partition.dev_regions[i];

		if (dev_region.interrupt_count > SP_MAX_INTERRUPTS_PER_DEVICE) {
			dlog_error(
				"Interrupt count for device region exceeds "
				"limit.\n");
			ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
			continue;
		}

		for (uint8_t j = 0; j < dev_region.interrupt_count; j++) {
			k++;
			if (k > VM_MANIFEST_MAX_INTERRUPTS) {
				dlog_error(
					"Interrupt count for VM exceeds "
					"limit.\n");
				ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
				continue;
			}
		}
	}

	return ret_code;
}

static enum manifest_return_code parse_ffa_partition_package(
	struct mm_stage1_locked stage1_locked, struct fdt_node *node,
	struct manifest_vm *vm, ffa_vm_id_t vm_id, struct mpool *ppool)
{
	enum manifest_return_code ret = MANIFEST_ERROR_NOT_COMPATIBLE;
	uintpaddr_t sp_pkg_addr;
	paddr_t sp_pkg_start;
	paddr_t sp_pkg_end;
	struct sp_pkg_header *sp_pkg;
	size_t sp_header_dtb_size;
	paddr_t sp_dtb_addr;
	struct fdt sp_fdt;

	/*
	 * This must have been hinted as being an FF-A partition,
	 * return straight with failure if this is not the case.
	 */
	if (!vm->is_ffa_partition) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	TRY(read_uint64(node, "load_address", &sp_pkg_addr));
	if (!is_aligned(sp_pkg_addr, PAGE_SIZE)) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	/* Map top of package as a single page to extract the header */
	sp_pkg_start = pa_init(sp_pkg_addr);
	sp_pkg_end = pa_add(sp_pkg_start, PAGE_SIZE);
	sp_pkg = mm_identity_map(stage1_locked, sp_pkg_start,
				 pa_add(sp_pkg_start, PAGE_SIZE), MM_MODE_R,
				 ppool);
	CHECK(sp_pkg != NULL);

	dlog_verbose("Package load address %#x\n", sp_pkg_addr);

	if (sp_pkg->magic != SP_PKG_HEADER_MAGIC) {
		dlog_error("Invalid package magic.\n");
		goto exit_unmap;
	}

	if (sp_pkg->version != SP_PKG_HEADER_VERSION) {
		dlog_error("Invalid package version.\n");
		goto exit_unmap;
	}

	/* TODO: Do not map 2 pages. */
	sp_header_dtb_size = align_up(sp_pkg->pm_size, 2 * PAGE_SIZE);

	if ((vm_id != HF_PRIMARY_VM_ID) &&
	    (sp_header_dtb_size >= vm->secondary.mem_size)) {
		dlog_error("Invalid package header or DT size.\n");
		goto exit_unmap;
	}

	if (sp_header_dtb_size > PAGE_SIZE) {
		/* Map remainder of header + DTB  */
		sp_pkg_end = pa_add(sp_pkg_start, sp_header_dtb_size);

		sp_pkg = mm_identity_map(stage1_locked, sp_pkg_start,
					 sp_pkg_end, MM_MODE_R, ppool);
		CHECK(sp_pkg != NULL);
	}

	sp_dtb_addr = pa_add(sp_pkg_start, sp_pkg->pm_offset);

	/* Since the address is from pa_addr allow the cast */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	if (!fdt_init_from_ptr(&sp_fdt, (void *)pa_addr(sp_dtb_addr),
			       sp_pkg->pm_size)) {
		dlog_error("FDT failed validation.\n");
		goto exit_unmap;
	}

	ret = parse_ffa_manifest(&sp_fdt, vm);
	if (ret != MANIFEST_SUCCESS) {
		dlog_error("Error parsing partition manifest: %s.\n",
			   manifest_strerror(ret));
		goto exit_unmap;
	}

	if (vm->partition.load_addr != sp_pkg_addr) {
		dlog_warning(
			"Partition's load address at its manifest differs"
			" from specified in partition's package.\n");
		vm->partition.load_addr = sp_pkg_addr;
	}

exit_unmap:
	CHECK(mm_unmap(stage1_locked, sp_pkg_start, sp_pkg_end, ppool));

	return ret;
}

/**
 * Parse manifest from FDT.
 */
enum manifest_return_code manifest_init(struct mm_stage1_locked stage1_locked,
					struct manifest *manifest,
					struct memiter *manifest_fdt,
					struct mpool *ppool)
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

	TRY(read_bool(&hyp_node, "ffa_tee_enabled",
		      &manifest->ffa_tee_enabled));

	/* Iterate over reserved VM IDs and check no such nodes exist. */
	for (i = HF_VM_ID_BASE; i < HF_VM_ID_OFFSET; i++) {
		ffa_vm_id_t vm_id = (ffa_vm_id_t)i - HF_VM_ID_BASE;
		struct fdt_node vm_node = hyp_node;

		generate_vm_node_name(&vm_name, vm_id);
		if (fdt_find_child(&vm_node, &vm_name)) {
			return MANIFEST_ERROR_RESERVED_VM_ID;
		}
	}

	/* Iterate over VM nodes until we find one that does not exist. */
	for (i = 0; i <= MAX_VMS; ++i) {
		ffa_vm_id_t vm_id = HF_VM_ID_OFFSET + i;
		struct fdt_node vm_node = hyp_node;

		generate_vm_node_name(&vm_name, vm_id - HF_VM_ID_BASE);
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

		TRY(parse_vm_common(&vm_node, &manifest->vm[i], vm_id));

		CHECK(!manifest->vm[i].is_hyp_loaded ||
		      manifest->vm[i].is_ffa_partition);

		if (manifest->vm[i].is_ffa_partition &&
		    !manifest->vm[i].is_hyp_loaded) {
			TRY(parse_ffa_partition_package(stage1_locked, &vm_node,
							&manifest->vm[i], vm_id,
							ppool));
		} else {
			TRY(parse_vm(&vm_node, &manifest->vm[i], vm_id));
		}
	}

	if (!found_primary_vm && vm_id_is_current_world(HF_PRIMARY_VM_ID)) {
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
	case MANIFEST_ERROR_MALFORMED_DTB:
		return "Malformed device tree blob";
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
	case MANIFEST_ERROR_MEMORY_REGION_NODE_EMPTY:
		return "Memory-region node should have at least one entry";
	case MANIFEST_ERROR_DEVICE_REGION_NODE_EMPTY:
		return "Device-region node should have at least one entry";
	case MANIFEST_ERROR_RXTX_SIZE_MISMATCH:
		return "RX and TX buffers should be of same size";
	case MANIFEST_ERROR_INVALID_MEM_PERM:
		return "Memory permission should be RO, RW or RX";
	}

	panic("Unexpected manifest return code.");
}
