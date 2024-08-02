/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/manifest.h"

#include <stddef.h>
#include <stdint.h>

#include "hf/arch/types.h"
#include "hf/arch/vmid_base.h"

#include "hf/addr.h"
#include "hf/assert.h"
#include "hf/boot_info.h"
#include "hf/boot_params.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/fdt.h"
#include "hf/ffa.h"
#include "hf/layout.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/sp_pkg.h"
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

/* Bitmap to track boot order values in use. */
#define BOOT_ORDER_ENTRY_BITS (sizeof(uint64_t) * 8)
#define BOOT_ORDER_MAP_ENTRIES                                \
	((DEFAULT_BOOT_ORDER + (BOOT_ORDER_ENTRY_BITS - 1)) / \
	 BOOT_ORDER_ENTRY_BITS)

/**
 * A struct to keep track of the partitions properties during early boot
 * manifest parsing:
 * - Interrupts ID.
 * - Physical memory ranges.
 */
struct manifest_data {
	struct manifest manifest;
	struct interrupt_bitmap intids;
	/*
	 * Allocate enough for the maximum amount of memory regions defined via
	 * the partitions manifest, and regions for each partition
	 * address-space.
	 */
	struct mem_range mem_regions[PARTITION_MAX_MEMORY_REGIONS * MAX_VMS +
				     PARTITION_MAX_DEVICE_REGIONS * MAX_VMS +
				     MAX_VMS];
	size_t mem_regions_index;
	uint64_t boot_order_values[BOOT_ORDER_MAP_ENTRIES];
};

/**
 * Calculate the number of entries in the ppool that are required to
 * store the manifest_data struct.
 */
static const size_t manifest_data_ppool_entries =
	(align_up(sizeof(struct manifest_data), MM_PPOOL_ENTRY_SIZE) /
	 MM_PPOOL_ENTRY_SIZE);

static struct manifest_data *manifest_data;

static bool check_boot_order(uint16_t boot_order)
{
	uint16_t i;
	uint64_t boot_order_mask;

	if (boot_order == DEFAULT_BOOT_ORDER) {
		return true;
	}
	if (boot_order > DEFAULT_BOOT_ORDER) {
		dlog_error("Boot order should not exceed %x",
			   DEFAULT_BOOT_ORDER);
		return false;
	}

	i = boot_order / BOOT_ORDER_ENTRY_BITS;
	boot_order_mask = 1 << (boot_order % BOOT_ORDER_ENTRY_BITS);

	if ((boot_order_mask & manifest_data->boot_order_values[i]) != 0U) {
		dlog_error("Boot order must be a unique value.");
		return false;
	}

	manifest_data->boot_order_values[i] |= boot_order_mask;

	return true;
}

/**
 * Allocates and clear memory for the manifest data in the given memory pool.
 * Returns true if the memory is successfully allocated.
 */
static bool manifest_data_init(struct mpool *ppool)
{
	manifest_data = (struct manifest_data *)mpool_alloc_contiguous(
		ppool, manifest_data_ppool_entries, 1);

	assert(manifest_data != NULL);

	memset_s(manifest_data, sizeof(struct manifest_data), 0,
		 sizeof(struct manifest_data));

	return manifest_data != NULL;
}

/**
 * Frees the memory used for the manifest data in the given memory pool.
 */
static void manifest_data_deinit(struct mpool *ppool)
{
	/**
	 * Clear and return the memory used for the manifest_data struct to the
	 * memory pool.
	 */
	memset_s(manifest_data, sizeof(struct manifest_data), 0,
		 sizeof(struct manifest_data));
	mpool_add_chunk(ppool, manifest_data, manifest_data_ppool_entries);
}

static inline size_t count_digits(ffa_id_t vm_id)
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
static void generate_vm_node_name(struct string *str, ffa_id_t vm_id)
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

	return ret;
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

/**
 * Parse a UUID from `uuid` into `out`.
 * Returns `MANIFEST_SUCCESS` if parsing succeeded.
 */
static enum manifest_return_code parse_uuid(struct uint32list_iter *uuid,
					    struct ffa_uuid *out)
{
	for (size_t i = 0; i < 4 && uint32list_has_next(uuid); i++) {
		TRY(uint32list_get_next(uuid, &out->uuid[i]));
	}

	return MANIFEST_SUCCESS;
}

/**
 * Parse a list of UUIDs from `uuid` into `out`.
 * Writes the number of UUIDs parsed to `len`.
 * Returns `MANIFEST_SUCCESS` if parsing succeeded.
 * Returns `MANIFEST_ERROR_UUID_ALL_ZEROS` if any of the UUIDs are all zeros.
 * Returns `MANIFEEST_ERROR_TOO_MANY_UUIDS` if there are more than
 * `PARTITION_MAX_UUIDS`
 */
static enum manifest_return_code parse_uuid_list(struct uint32list_iter *uuid,
						 struct ffa_uuid *out,
						 uint16_t *len)
{
	uint16_t j;

	for (j = 0; uint32list_has_next(uuid); j++) {
		TRY(parse_uuid(uuid, &out[j]));

		if (ffa_uuid_is_null(&out[j])) {
			return MANIFEST_ERROR_UUID_ALL_ZEROS;
		}
		dlog_verbose("  UUID %#x-%x-%x-%x\n", out[j].uuid[0],
			     out[j].uuid[1], out[j].uuid[2], out[j].uuid[3]);

		if (j >= PARTITION_MAX_UUIDS) {
			return MANIFEST_ERROR_TOO_MANY_UUIDS;
		}
	}

	*len = j;
	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_vm_common(const struct fdt_node *node,
						 struct manifest_vm *vm,
						 ffa_id_t vm_id)
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
		dlog_warning("%s SMC whitelist too long.\n",
			     vm->debug_name.data);
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
					  ffa_id_t vm_id)
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

static bool is_memory_region_within_ranges(uintptr_t base_address,
					   uint32_t page_count,
					   const struct mem_range *ranges,
					   const size_t ranges_size)
{
	uintptr_t region_end =
		base_address + ((uintptr_t)page_count * PAGE_SIZE - 1);

	for (size_t i = 0; i < ranges_size; i++) {
		uintptr_t base = (uintptr_t)pa_addr(ranges[i].begin);
		uintptr_t end = (uintptr_t)pa_addr(ranges[i].end);

		if ((base_address >= base && base_address <= end) ||
		    (region_end >= base && region_end <= end)) {
			return true;
		}
	}

	return false;
}

void dump_memory_ranges(const struct mem_range *ranges,
			const size_t ranges_size, bool ns)
{
	if (LOG_LEVEL < LOG_LEVEL_VERBOSE) {
		return;
	}

	dlog("%s Memory ranges:\n", ns ? "NS" : "S");

	for (size_t i = 0; i < ranges_size; i++) {
		uintptr_t begin = pa_addr(ranges[i].begin);
		uintptr_t end = pa_addr(ranges[i].end);
		size_t page_count =
			align_up(pa_difference(ranges[i].begin, ranges[i].end),
				 PAGE_SIZE) /
			PAGE_SIZE;

		dlog("  [%lx - %lx (%zu pages)]\n", begin, end, page_count);
	}
}

/**
 * Check the partition's assigned memory is contained in the memory ranges
 * configured for the SWd, in the SPMC's manifest.
 */
static enum manifest_return_code check_partition_memory_is_valid(
	uintptr_t base_address, uint32_t page_count, uint32_t attributes,
	const struct boot_params *params, bool is_device_region)
{
	bool is_secure_region =
		(attributes & MANIFEST_REGION_ATTR_SECURITY) == 0U;
	const struct mem_range *ranges_from_manifest;
	size_t ranges_count;
	bool within_ranges;
	enum manifest_return_code error_return;

	if (!is_device_region) {
		ranges_from_manifest = is_secure_region ? params->mem_ranges
							: params->ns_mem_ranges;
		ranges_count = is_secure_region ? params->mem_ranges_count
						: params->ns_mem_ranges_count;
		error_return = MANIFEST_ERROR_MEM_REGION_INVALID;
	} else {
		ranges_from_manifest = is_secure_region
					       ? params->device_mem_ranges
					       : params->ns_device_mem_ranges;
		ranges_count = is_secure_region
				       ? params->device_mem_ranges_count
				       : params->ns_device_mem_ranges_count;
		error_return = MANIFEST_ERROR_DEVICE_MEM_REGION_INVALID;
	}

	within_ranges = is_memory_region_within_ranges(
		base_address, page_count, ranges_from_manifest, ranges_count);

	return within_ranges ? MANIFEST_SUCCESS : error_return;
}

/*
 * Keep track of the memory allocated by partitions. This includes memory region
 * nodes and device region nodes defined in their respective partition
 * manifests, as well address space defined from their load address.
 */
static enum manifest_return_code check_and_record_memory_used(
	uintptr_t base_address, uint32_t page_count,
	struct mem_range *mem_ranges, size_t *mem_regions_index)
{
	bool overlap_of_regions;

	if (page_count == 0U) {
		dlog_error(
			"Empty memory region defined with base address: "
			"%#lx.\n",
			base_address);
		return MANIFEST_ERROR_MEM_REGION_EMPTY;
	}

	if (!is_aligned(base_address, PAGE_SIZE)) {
		dlog_error("base_address (%#lx) is not aligned to page size.\n",
			   base_address);
		return MANIFEST_ERROR_MEM_REGION_UNALIGNED;
	}

	overlap_of_regions = is_memory_region_within_ranges(
		base_address, page_count, mem_ranges, *mem_regions_index);

	if (!overlap_of_regions) {
		paddr_t begin = pa_init(base_address);

		mem_ranges[*mem_regions_index].begin = begin;
		mem_ranges[*mem_regions_index].end =
			pa_add(begin, page_count * PAGE_SIZE - 1);
		(*mem_regions_index)++;

		return MANIFEST_SUCCESS;
	}

	return MANIFEST_ERROR_MEM_REGION_OVERLAP;
}

static enum manifest_return_code parse_common_fields_mem_dev_region_node(
	struct fdt_node *ffa_node, struct dma_device_properties *dma_prop)
{
	uint32_t j = 0;
	struct uint32list_iter list;

	TRY(read_optional_uint32(ffa_node, "smmu-id", MANIFEST_INVALID_ID,
				 &dma_prop->smmu_id));
	if (dma_prop->smmu_id != MANIFEST_INVALID_ID) {
		dlog_verbose("      smmu-id:  %u\n", dma_prop->smmu_id);
	}

	TRY(read_optional_uint32list(ffa_node, "stream-ids", &list));
	dlog_verbose("      Stream IDs assigned:\n");

	j = 0;
	while (uint32list_has_next(&list)) {
		if (j == PARTITION_MAX_STREAMS_PER_DEVICE) {
			return MANIFEST_ERROR_STREAM_IDS_OVERFLOW;
		}

		TRY(uint32list_get_next(&list, &dma_prop->stream_ids[j]));
		dlog_verbose("        %u\n", dma_prop->stream_ids[j]);
		j++;
	}
	if (j == 0) {
		dlog_verbose("        None\n");
	} else if (dma_prop->smmu_id == MANIFEST_INVALID_ID) {
		/*
		 * SMMU ID must be specified if the partition specifies
		 * Stream IDs for any device upstream of SMMU.
		 */
		return MANIFEST_ERROR_MISSING_SMMU_ID;
	}
	dma_prop->stream_count = j;

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code parse_ffa_memory_region_node(
	struct fdt_node *mem_node, uintptr_t load_address,
	struct memory_region *mem_regions, uint16_t *count, struct rx_tx *rxtx,
	const struct boot_params *boot_params)
{
	uint32_t phandle;
	uint16_t i = 0;
	uint32_t j = 0;
	uintptr_t relative_address;
	struct uint32list_iter list;

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
		dlog_verbose("      Base address: %#lx\n",
			     mem_regions[i].base_address);

		TRY(read_optional_uint64(
			mem_node, "load-address-relative-offset",
			MANIFEST_INVALID_ADDRESS, &relative_address));
		if (relative_address != MANIFEST_INVALID_ADDRESS) {
			dlog_verbose("      Relative address:  %#lx\n",
				     relative_address);
		}

		if (mem_regions[i].base_address == MANIFEST_INVALID_ADDRESS &&
		    relative_address == MANIFEST_INVALID_ADDRESS) {
			return MANIFEST_ERROR_PROPERTY_NOT_FOUND;
		}

		if (mem_regions[i].base_address != MANIFEST_INVALID_ADDRESS &&
		    relative_address != MANIFEST_INVALID_ADDRESS) {
			return MANIFEST_ERROR_BASE_ADDRESS_AND_RELATIVE_ADDRESS;
		}

		if (relative_address != MANIFEST_INVALID_ADDRESS &&
		    relative_address > UINT64_MAX - load_address) {
			return MANIFEST_ERROR_INTEGER_OVERFLOW;
		}

		if (relative_address != MANIFEST_INVALID_ADDRESS) {
			mem_regions[i].base_address =
				load_address + relative_address;
		}

		TRY(read_uint32(mem_node, "pages-count",
				&mem_regions[i].page_count));
		dlog_verbose("      Pages_count: %u\n",
			     mem_regions[i].page_count);

		TRY(read_uint32(mem_node, "attributes",
				&mem_regions[i].attributes));

		/*
		 * Check RWX permission attributes.
		 * Security attribute is checked at load phase.
		 */
		uint32_t permissions = mem_regions[i].attributes &
				       (MANIFEST_REGION_ATTR_READ |
					MANIFEST_REGION_ATTR_WRITE |
					MANIFEST_REGION_ATTR_EXEC);
		if (permissions != MANIFEST_REGION_ATTR_READ &&
		    permissions != (MANIFEST_REGION_ATTR_READ |
				    MANIFEST_REGION_ATTR_WRITE) &&
		    permissions != (MANIFEST_REGION_ATTR_READ |
				    MANIFEST_REGION_ATTR_EXEC)) {
			return MANIFEST_ERROR_INVALID_MEM_PERM;
		}

		/* Filter memory region attributes. */
		mem_regions[i].attributes &= MANIFEST_REGION_ALL_ATTR_MASK;

		dlog_verbose("      Attributes: %#x\n",
			     mem_regions[i].attributes);

		TRY(check_partition_memory_is_valid(
			mem_regions[i].base_address, mem_regions[i].page_count,
			mem_regions[i].attributes, boot_params, false));

		TRY(check_and_record_memory_used(
			mem_regions[i].base_address, mem_regions[i].page_count,
			manifest_data->mem_regions,
			&manifest_data->mem_regions_index));

		TRY(parse_common_fields_mem_dev_region_node(
			mem_node, &mem_regions[i].dma_prop));

		TRY(read_optional_uint32list(
			mem_node, "stream-ids-access-permissions", &list));
		dlog_verbose("      Access permissions of Stream IDs:\n");

		j = 0;
		while (uint32list_has_next(&list)) {
			uint32_t permissions;

			if (j == PARTITION_MAX_STREAMS_PER_DEVICE) {
				return MANIFEST_ERROR_DMA_ACCESS_PERMISSIONS_OVERFLOW;
			}

			TRY(uint32list_get_next(&list, &permissions));
			dlog_verbose("        %u\n", permissions);

			if (j == 0) {
				mem_regions[i].dma_access_permissions =
					permissions;
			}

			/*
			 * All stream ids belonging to a dma device must specify
			 * the same access permissions.
			 */
			if (permissions !=
			    mem_regions[i].dma_access_permissions) {
				return MANIFEST_ERROR_MISMATCH_DMA_ACCESS_PERMISSIONS;
			}

			j++;
		}

		if (j == 0) {
			dlog_verbose("        None\n");
		} else if (j != mem_regions[i].dma_prop.stream_count) {
			return MANIFEST_ERROR_MISMATCH_DMA_ACCESS_PERMISSIONS;
		}

		if (j > 0) {
			/* Filter the dma access permissions. */
			mem_regions[i].dma_access_permissions &=
				MANIFEST_REGION_ALL_ATTR_MASK;
		}

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
	} while (fdt_next_sibling(mem_node) &&
		 (i < PARTITION_MAX_MEMORY_REGIONS));

	if (rxtx->available &&
	    (rxtx->rx_buffer->page_count != rxtx->tx_buffer->page_count)) {
		return MANIFEST_ERROR_RXTX_SIZE_MISMATCH;
	}

	*count = i;

	return MANIFEST_SUCCESS;
}

static struct interrupt_info *device_region_get_interrupt_info(
	struct device_region *dev_regions, uint32_t intid)
{
	for (uint32_t i = 0; i < ARRAY_SIZE(dev_regions->interrupts); i++) {
		if (dev_regions->interrupts[i].id == intid) {
			return &(dev_regions->interrupts[i]);
		}
	}
	return NULL;
}

static enum manifest_return_code parse_ffa_device_region_node(
	struct fdt_node *dev_node, struct device_region *dev_regions,
	uint16_t *count, uint8_t *dma_device_count,
	const struct boot_params *boot_params)
{
	struct uint32list_iter list;
	uint16_t i = 0;
	uint32_t j = 0;
	struct interrupt_bitmap allocated_intids = manifest_data->intids;
	uint8_t dma_device_id = 0;

	dlog_verbose("  Partition Device Regions\n");

	if (!fdt_is_compatible(dev_node, "arm,ffa-manifest-device-regions")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (!fdt_first_child(dev_node)) {
		return MANIFEST_ERROR_DEVICE_REGION_NODE_EMPTY;
	}

	*dma_device_count = 0;

	do {
		dlog_verbose("    Device Region[%u]\n", i);

		TRY(read_optional_string(dev_node, "description",
					 &dev_regions[i].name));
		dlog_verbose("      Name: %s\n",
			     string_data(&dev_regions[i].name));

		TRY(read_uint64(dev_node, "base-address",
				&dev_regions[i].base_address));
		dlog_verbose("      Base address: %#lx\n",
			     dev_regions[i].base_address);

		TRY(read_uint32(dev_node, "pages-count",
				&dev_regions[i].page_count));
		dlog_verbose("      Pages_count: %u\n",
			     dev_regions[i].page_count);

		TRY(check_and_record_memory_used(
			dev_regions[i].base_address, dev_regions[i].page_count,
			manifest_data->mem_regions,
			&manifest_data->mem_regions_index));

		TRY(read_uint32(dev_node, "attributes",
				&dev_regions[i].attributes));

		/*
		 * Check RWX permission attributes.
		 * Security attribute is checked at load phase.
		 */
		uint32_t permissions = dev_regions[i].attributes &
				       (MANIFEST_REGION_ATTR_READ |
					MANIFEST_REGION_ATTR_WRITE |
					MANIFEST_REGION_ATTR_EXEC);

		if (permissions != MANIFEST_REGION_ATTR_READ &&
		    permissions != (MANIFEST_REGION_ATTR_READ |
				    MANIFEST_REGION_ATTR_WRITE)) {
			return MANIFEST_ERROR_INVALID_MEM_PERM;
		}

		/* Filter device region attributes. */
		dev_regions[i].attributes = dev_regions[i].attributes &
					    MANIFEST_REGION_ALL_ATTR_MASK;

		dlog_verbose("      Attributes: %#x\n",
			     dev_regions[i].attributes);

		TRY(check_partition_memory_is_valid(
			dev_regions[i].base_address, dev_regions[i].page_count,
			dev_regions[i].attributes, boot_params, true));

		TRY(read_optional_uint32list(dev_node, "interrupts", &list));
		dlog_verbose("      Interrupt List:\n");
		j = 0;
		while (uint32list_has_next(&list) &&
		       j < PARTITION_MAX_INTERRUPTS_PER_DEVICE) {
			uint32_t intid;

			TRY(uint32list_get_next(
				&list, &dev_regions[i].interrupts[j].id));
			intid = dev_regions[i].interrupts[j].id;

			dlog_verbose("        ID = %u\n", intid);

			if (interrupt_bitmap_get_value(&allocated_intids,
						       intid) == 1U) {
				return MANIFEST_ERROR_INTERRUPT_ID_REPEATED;
			}

			interrupt_bitmap_set_value(&allocated_intids, intid);

			if (uint32list_has_next(&list)) {
				TRY(uint32list_get_next(&list,
							&dev_regions[i]
								 .interrupts[j]
								 .attributes));
			} else {
				return MANIFEST_ERROR_MALFORMED_INTEGER_LIST;
			}

			dev_regions[i].interrupts[j].mpidr_valid = false;
			dev_regions[i].interrupts[j].mpidr = 0;

			dlog_verbose("        attributes = %u\n",
				     dev_regions[i].interrupts[j].attributes);
			j++;
		}

		dev_regions[i].interrupt_count = j;
		if (j == 0) {
			dlog_verbose("        Empty\n");
		} else {
			TRY(read_optional_uint32list(
				dev_node, "interrupts-target", &list));
			dlog_verbose("      Interrupt Target List:\n");

			while (uint32list_has_next(&list)) {
				uint32_t intid;
				uint64_t mpidr = 0;
				uint32_t mpidr_lower = 0;
				uint32_t mpidr_upper = 0;
				struct interrupt_info *info = NULL;

				TRY(uint32list_get_next(&list, &intid));

				dlog_verbose("        ID = %u\n", intid);

				if (interrupt_bitmap_get_value(
					    &allocated_intids, intid) != 1U) {
					return MANIFEST_ERROR_INTERRUPT_ID_NOT_IN_LIST;
				}

				TRY(uint32list_get_next(&list, &mpidr_upper));
				TRY(uint32list_get_next(&list, &mpidr_lower));
				mpidr = mpidr_upper;
				mpidr <<= 32;
				mpidr |= mpidr_lower;

				info = device_region_get_interrupt_info(
					&dev_regions[i], intid);
				/*
				 * We should find info since
				 * interrupt_bitmap_get_value already ensures
				 * that we saw the interrupt and allocated ids
				 * for it.
				 */
				assert(info != NULL);
				info->mpidr = mpidr;
				info->mpidr_valid = true;
				dlog_verbose("        MPIDR = %#lx\n", mpidr);
			}
		}

		TRY(parse_common_fields_mem_dev_region_node(
			dev_node, &dev_regions[i].dma_prop));

		if (dev_regions[i].dma_prop.smmu_id != MANIFEST_INVALID_ID) {
			dev_regions[i].dma_prop.dma_device_id = dma_device_id++;
			*dma_device_count = dma_device_id;

			if (*dma_device_count > PARTITION_MAX_DMA_DEVICES) {
				return MANIFEST_ERROR_DMA_DEVICE_OVERFLOW;
			}

			dlog_verbose("      dma peripheral device id:  %u\n",
				     dev_regions[i].dma_prop.dma_device_id);
		}

		TRY(read_bool(dev_node, "exclusive-access",
			      &dev_regions[i].exclusive_access));
		dlog_verbose("      Exclusive_access: %u\n",
			     dev_regions[i].exclusive_access);

		i++;
	} while (fdt_next_sibling(dev_node) &&
		 (i < PARTITION_MAX_DEVICE_REGIONS));

	*count = i;

	return MANIFEST_SUCCESS;
}

static enum manifest_return_code sanity_check_ffa_manifest(
	struct manifest_vm *vm)
{
	enum ffa_version ffa_version;
	enum manifest_return_code ret_code = MANIFEST_SUCCESS;
	const char *error_string = "specified in manifest is unsupported";
	uint32_t k = 0;
	bool using_req2 = (vm->partition.messaging_method &
			   (FFA_PARTITION_DIRECT_REQ2_RECV |
			    FFA_PARTITION_DIRECT_REQ2_SEND)) != 0;

	/* ensure that the SPM version is compatible */
	ffa_version = vm->partition.ffa_version;
	if (!ffa_versions_are_compatible(ffa_version, FFA_VERSION_COMPILED)) {
		dlog_error("FF-A partition manifest version %s: %u.%u\n",
			   error_string, ffa_version_get_major(ffa_version),
			   ffa_version_get_minor(ffa_version));
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
	    vm->partition.run_time_el != S_EL0 &&
	    vm->partition.run_time_el != EL0) {
		dlog_error("Exception level %s: %d\n", error_string,
			   vm->partition.run_time_el);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if (vm->partition.ffa_version < FFA_VERSION_1_2 && using_req2) {
		dlog_error("Messaging method %s: %x\n", error_string,
			   vm->partition.messaging_method);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if ((vm->partition.messaging_method &
	     ~(FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_DIRECT_REQ_SEND |
	       FFA_PARTITION_INDIRECT_MSG | FFA_PARTITION_DIRECT_REQ2_RECV |
	       FFA_PARTITION_DIRECT_REQ2_SEND)) != 0U) {
		dlog_error("Messaging method %s: %x\n", error_string,
			   vm->partition.messaging_method);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	if ((vm->partition.run_time_el == S_EL0 ||
	     vm->partition.run_time_el == EL0) &&
	    vm->partition.execution_ctx_count != 1) {
		dlog_error(
			"Exception level and execution context count %s: %d "
			"%d\n",
			error_string, vm->partition.run_time_el,
			vm->partition.execution_ctx_count);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	for (uint16_t i = 0; i < vm->partition.dev_region_count; i++) {
		struct device_region dev_region;

		dev_region = vm->partition.dev_regions[i];

		if (dev_region.interrupt_count >
		    PARTITION_MAX_INTERRUPTS_PER_DEVICE) {
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

	/* GP register is restricted to one of x0 - x3. */
	if (vm->partition.gp_register_num != DEFAULT_BOOT_GP_REGISTER &&
	    vm->partition.gp_register_num > 3) {
		dlog_error("GP register number %s: %u\n", error_string,
			   vm->partition.gp_register_num);
		ret_code = MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	return ret_code;
}

/**
 * Find the device id allocated to the device region node corresponding to the
 * specified stream id.
 */
static bool find_dma_device_id_from_dev_region_nodes(
	const struct manifest_vm *manifest_vm, uint32_t sid, uint8_t *device_id)
{
	for (uint16_t i = 0; i < manifest_vm->partition.dev_region_count; i++) {
		struct device_region dev_region =
			manifest_vm->partition.dev_regions[i];

		for (uint8_t j = 0; j < dev_region.dma_prop.stream_count; j++) {
			if (sid == dev_region.dma_prop.stream_ids[j]) {
				*device_id = dev_region.dma_prop.dma_device_id;
				return true;
			}
		}
	}
	return false;
}

/**
 * Identify the device id of a DMA device node corresponding to a stream id
 * specified in the memory region node.
 */
static bool map_dma_device_id_to_stream_ids(struct manifest_vm *vm)
{
	for (uint16_t i = 0; i < vm->partition.mem_region_count; i++) {
		struct memory_region mem_region = vm->partition.mem_regions[i];

		for (uint8_t j = 0; j < mem_region.dma_prop.stream_count; j++) {
			uint32_t sid = mem_region.dma_prop.stream_ids[j];
			uint8_t device_id = 0;

			/*
			 * Every stream id must have been declared in the
			 * device node as well.
			 */
			if (!find_dma_device_id_from_dev_region_nodes(
				    vm, sid, &device_id)) {
				dlog_verbose(
					"Stream ID %d not found in any device "
					"region node of partition manifest\n",
					sid);
				return false;
			}

			mem_region.dma_prop.dma_device_id = device_id;
		}
	}

	return true;
}

enum manifest_return_code parse_ffa_manifest(
	struct fdt *fdt, struct manifest_vm *vm,
	struct fdt_node *boot_info_node, const struct boot_params *boot_params)
{
	struct uint32list_iter uuid;
	uintpaddr_t load_address;
	struct fdt_node root;
	struct fdt_node ffa_node;
	struct string rxtx_node_name = STRING_INIT("rx_tx-info");
	struct string mem_region_node_name = STRING_INIT("memory-regions");
	struct string dev_region_node_name = STRING_INIT("device-regions");
	struct string boot_info_node_name = STRING_INIT("boot-info");
	bool managed_exit_field_present = false;

	if (!fdt_find_node(fdt, "/", &root)) {
		return MANIFEST_ERROR_NO_ROOT_NODE;
	}

	/* Check "compatible" property. */
	if (!fdt_is_compatible(&root, "arm,ffa-manifest-1.0")) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	TRY(read_uint32list(&root, "uuid", &uuid));

	TRY(parse_uuid_list(&uuid, vm->partition.uuids,
			    &vm->partition.uuid_count));
	dlog_verbose("  Number of UUIDs %u\n", vm->partition.uuid_count);

	TRY(read_uint32(&root, "ffa-version", &vm->partition.ffa_version));
	dlog_verbose("  Expected FF-A version %u.%u\n",
		     ffa_version_get_major(vm->partition.ffa_version),
		     ffa_version_get_minor(vm->partition.ffa_version));

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

	TRY(read_optional_uint64(&root, "load-address", 0, &load_address));
	if (vm->partition.load_addr != load_address) {
		dlog_warning(
			"Partition's load address at its manifest differs"
			" from specified in partition's package.\n");
	}
	dlog_verbose("  Load address %#lx\n", vm->partition.load_addr);

	TRY(read_optional_uint64(&root, "entrypoint-offset", 0,
				 &vm->partition.ep_offset));
	dlog_verbose("  Entry point offset %#zx\n", vm->partition.ep_offset);

	TRY(read_optional_uint32(&root, "gp-register-num",
				 DEFAULT_BOOT_GP_REGISTER,
				 &vm->partition.gp_register_num));

	if (vm->partition.gp_register_num != DEFAULT_BOOT_GP_REGISTER) {
		dlog_verbose("  Boot GP register: x%u\n",
			     vm->partition.gp_register_num);
	}

	TRY(read_optional_uint16(&root, "boot-order", DEFAULT_BOOT_ORDER,
				 &vm->partition.boot_order));
	if (vm->partition.boot_order != DEFAULT_BOOT_ORDER) {
		dlog_verbose("  Boot order %u\n", vm->partition.boot_order);
	}

	if (!check_boot_order(vm->partition.boot_order)) {
		return MANIFEST_ERROR_INVALID_BOOT_ORDER;
	}

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

	TRY(read_uint16(&root, "messaging-method",
			(uint16_t *)&vm->partition.messaging_method));
	dlog_verbose("  Messaging method %u\n", vm->partition.messaging_method);

	TRY(read_bool(&root, "managed-exit", &managed_exit_field_present));

	TRY(read_optional_uint8(
		&root, "ns-interrupts-action", NS_ACTION_SIGNALED,
		(uint8_t *)&vm->partition.ns_interrupts_action));

	/*
	 * An SP manifest can specify one of the fields listed below:
	 * `managed-exit`: Introduced in FF-A v1.0 spec.
	 * `ns-interrupts-action`: Introduced in FF-A v1.1 EAC0 spec.
	 * If both are missing from the manifest, the default response is
	 * NS_ACTION_SIGNALED.
	 */
	if (managed_exit_field_present) {
		vm->partition.ns_interrupts_action = NS_ACTION_ME;
	}

	if (vm->partition.ns_interrupts_action != NS_ACTION_QUEUED &&
	    vm->partition.ns_interrupts_action != NS_ACTION_ME &&
	    vm->partition.ns_interrupts_action != NS_ACTION_SIGNALED) {
		return MANIFEST_ERROR_ILLEGAL_NS_INT_ACTION;
	}

	dlog_verbose(
		"  NS Interrupts %s\n",
		(vm->partition.ns_interrupts_action == NS_ACTION_QUEUED)
			? "Queued"
		: (vm->partition.ns_interrupts_action == NS_ACTION_SIGNALED)
			? "Signaled"
			: "Managed exit");

	if (vm->partition.ns_interrupts_action == NS_ACTION_ME) {
		/* Managed exit only supported by S_EL1 partitions. */
		if (vm->partition.run_time_el != S_EL1) {
			dlog_error(
				"Managed exit cannot be supported by this "
				"partition\n");
			return MANIFEST_ERROR_ILLEGAL_NS_INT_ACTION;
		}

		TRY(read_bool(&root, "managed-exit-virq",
			      &vm->partition.me_signal_virq));
		if (vm->partition.me_signal_virq) {
			dlog_verbose("  Managed Exit signaled through vIRQ\n");
		}
	}

	TRY(read_bool(&root, "notification-support",
		      &vm->partition.notification_support));
	if (vm->partition.notification_support) {
		dlog_verbose("  Notifications Receipt Supported\n");
	}

	TRY(read_optional_uint8(
		&root, "other-s-interrupts-action", OTHER_S_INT_ACTION_SIGNALED,
		(uint8_t *)&vm->partition.other_s_interrupts_action));

	if (vm->partition.other_s_interrupts_action ==
	    OTHER_S_INT_ACTION_QUEUED) {
		if (vm->partition.ns_interrupts_action != NS_ACTION_QUEUED) {
			dlog_error(
				"Choice of the fields 'ns-interrupts-action' "
				"and 'other-s-interrupts-action' not "
				"compatible\n");
			return MANIFEST_ERROR_NOT_COMPATIBLE;
		}
	} else if (vm->partition.other_s_interrupts_action >
		   OTHER_S_INT_ACTION_SIGNALED) {
		dlog_error(
			"Illegal value specified for the field "
			"'other-s-interrupts-action': %u\n",
			vm->partition.other_s_interrupts_action);
		return MANIFEST_ERROR_ILLEGAL_OTHER_S_INT_ACTION;
	}

	/* Parse boot info node. */
	if (boot_info_node != NULL) {
		ffa_node = root;
		vm->partition.boot_info =
			fdt_find_child(&ffa_node, &boot_info_node_name);
		if (vm->partition.boot_info) {
			*boot_info_node = ffa_node;
		}
	} else {
		vm->partition.boot_info = false;
	}

	TRY(read_optional_uint32(
		&root, "vm-availability-messages", 0,
		(uint32_t *)&vm->partition.vm_availability_messages));
	dlog_verbose("vm-availability-messages=%#x\n",
		     *(uint32_t *)&vm->partition.vm_availability_messages);

	if (vm->partition.vm_availability_messages.mbz != 0) {
		return MANIFEST_ERROR_VM_AVAILABILITY_MESSAGE_INVALID;
	}

	TRY(read_optional_uint32(
		&root, "power-management-messages",
		MANIFEST_POWER_MANAGEMENT_CPU_OFF_SUPPORTED |
			MANIFEST_POWER_MANAGEMENT_CPU_ON_SUPPORTED,
		&vm->partition.power_management));
	vm->partition.power_management &= MANIFEST_POWER_MANAGEMENT_ALL_MASK;
	if (vm->partition.execution_ctx_count == 1 ||
	    vm->partition.run_time_el == S_EL0 ||
	    vm->partition.run_time_el == EL0) {
		vm->partition.power_management =
			MANIFEST_POWER_MANAGEMENT_NONE_MASK;
	}

	dlog_verbose("  Power management messages %#x\n",
		     vm->partition.power_management);

	/* Parse memory-regions */
	ffa_node = root;
	if (fdt_find_child(&ffa_node, &mem_region_node_name)) {
		TRY(parse_ffa_memory_region_node(
			&ffa_node, vm->partition.load_addr,
			vm->partition.mem_regions,
			&vm->partition.mem_region_count, &vm->partition.rxtx,
			boot_params));
	}
	dlog_verbose("  Total %u memory regions found\n",
		     vm->partition.mem_region_count);

	/* Parse Device-regions */
	ffa_node = root;
	if (fdt_find_child(&ffa_node, &dev_region_node_name)) {
		TRY(parse_ffa_device_region_node(
			&ffa_node, vm->partition.dev_regions,
			&vm->partition.dev_region_count,
			&vm->partition.dma_device_count, boot_params));
	}
	dlog_verbose("  Total %u device regions found\n",
		     vm->partition.dev_region_count);

	if (!map_dma_device_id_to_stream_ids(vm)) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	return sanity_check_ffa_manifest(vm);
}

static enum manifest_return_code parse_ffa_partition_package(
	struct mm_stage1_locked stage1_locked, struct fdt_node *node,
	struct manifest_vm *vm, ffa_id_t vm_id,
	const struct boot_params *boot_params, struct mpool *ppool)
{
	enum manifest_return_code ret = MANIFEST_ERROR_NOT_COMPATIBLE;
	uintpaddr_t load_address;
	struct sp_pkg_header header;
	struct fdt sp_fdt;
	vaddr_t pkg_start;
	vaddr_t manifest_address;
	struct fdt_node boot_info_node;

	/*
	 * This must have been hinted as being an FF-A partition,
	 * return straight with failure if this is not the case.
	 */
	if (!vm->is_ffa_partition) {
		return ret;
	}

	TRY(read_uint64(node, "load_address", &load_address));
	if (!is_aligned(load_address, PAGE_SIZE)) {
		return MANIFEST_ERROR_NOT_COMPATIBLE;
	}

	assert(load_address != 0U);

	if (!sp_pkg_init(stage1_locked, pa_init(load_address), &header,
			 ppool)) {
		return ret;
	}

	pkg_start = va_init(load_address);

	if (vm_id != HF_PRIMARY_VM_ID &&
	    sp_pkg_get_mem_size(&header) >= vm->secondary.mem_size) {
		dlog_error("Invalid package header or DT size.\n");
		goto out;
	}

	manifest_address = va_add(va_init(load_address), header.pm_offset);
	if (!fdt_init_from_ptr(&sp_fdt, ptr_from_va(manifest_address),
			       header.pm_size)) {
		dlog_error("manifest.c: FDT failed validation.\n");
		goto out;
	}

	vm->partition.load_addr = load_address;

	ret = parse_ffa_manifest(&sp_fdt, vm, &boot_info_node, boot_params);
	if (ret != MANIFEST_SUCCESS) {
		dlog_error("Error parsing partition manifest.\n");
		goto out;
	}

	if (vm->partition.gp_register_num != DEFAULT_BOOT_GP_REGISTER) {
		if (header.version == SP_PKG_HEADER_VERSION_2 &&
		    vm->partition.boot_info &&
		    !ffa_boot_info_node(&boot_info_node, pkg_start, &header)) {
			dlog_error("Failed to process boot information.\n");
		}
	}
out:
	sp_pkg_deinit(stage1_locked, pkg_start, &header, ppool);
	return ret;
}

/**
 * Parse manifest from FDT.
 */
enum manifest_return_code manifest_init(struct mm_stage1_locked stage1_locked,
					struct manifest **manifest_ret,
					struct memiter *manifest_fdt,
					struct boot_params *boot_params,
					struct mpool *ppool)
{
	struct manifest *manifest;
	struct string vm_name;
	struct fdt fdt;
	struct fdt_node hyp_node;
	size_t i = 0;
	bool found_primary_vm = false;
	const size_t spmc_size =
		align_up(pa_difference(layout_text_begin(), layout_image_end()),
			 PAGE_SIZE);
	const size_t spmc_page_count = spmc_size / PAGE_SIZE;

	if (boot_params->mem_ranges_count == 0 &&
	    boot_params->ns_mem_ranges_count == 0) {
		return MANIFEST_ERROR_MEMORY_MISSING;
	}

	dump_memory_ranges(boot_params->mem_ranges,
			   boot_params->mem_ranges_count, false);
	dump_memory_ranges(boot_params->ns_mem_ranges,
			   boot_params->ns_mem_ranges_count, true);

	/* Allocate space in the ppool for the manifest data. */
	if (!manifest_data_init(ppool)) {
		panic("Unable to allocate manifest data.\n");
	}

	/*
	 * Add SPMC load address range to memory ranges to track to ensure
	 * no partitions overlap with this memory.
	 * The system integrator should have prevented this by defining the
	 * secure memory region ranges so as not to overlap the SPMC load
	 * address range. Therefore, this code is intended to catch any
	 * potential misconfigurations there.
	 */
	if (is_aligned(pa_addr(layout_text_begin()), PAGE_SIZE) &&
	    spmc_page_count != 0) {
		TRY(check_and_record_memory_used(
			pa_addr(layout_text_begin()), spmc_page_count,
			manifest_data->mem_regions,
			&manifest_data->mem_regions_index));
	}

	manifest = &manifest_data->manifest;
	*manifest_ret = manifest;

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
		ffa_id_t vm_id = (ffa_id_t)i - HF_VM_ID_BASE;
		struct fdt_node vm_node = hyp_node;

		generate_vm_node_name(&vm_name, vm_id);
		if (fdt_find_child(&vm_node, &vm_name)) {
			return MANIFEST_ERROR_RESERVED_VM_ID;
		}
	}

	/* Iterate over VM nodes until we find one that does not exist. */
	for (i = 0; i <= MAX_VMS; ++i) {
		ffa_id_t vm_id = HF_VM_ID_OFFSET + i;
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
							boot_params, ppool));
			size_t page_count =
				align_up(manifest->vm[i].secondary.mem_size,
					 PAGE_SIZE) /
				PAGE_SIZE;

			if (vm_id == HF_PRIMARY_VM_ID) {
				continue;
			}

			TRY(check_partition_memory_is_valid(
				manifest->vm[i].partition.load_addr, page_count,
				0, boot_params, false));

			/*
			 * Check if memory from load-address until (load-address
			 * + memory size) has been used by other partition.
			 */
			TRY(check_and_record_memory_used(
				manifest->vm[i].partition.load_addr, page_count,
				manifest_data->mem_regions,
				&manifest_data->mem_regions_index));
		} else {
			TRY(parse_vm(&vm_node, &manifest->vm[i], vm_id));
		}
	}

	if (!found_primary_vm && vm_id_is_current_world(HF_PRIMARY_VM_ID)) {
		return MANIFEST_ERROR_NO_PRIMARY_VM;
	}

	return MANIFEST_SUCCESS;
}

/**
 * Free manifest data resources, called once manifest parsing has
 * completed and VMs are loaded.
 */
void manifest_deinit(struct mpool *ppool)
{
	manifest_data_deinit(ppool);
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
	case MANIFEST_ERROR_MEM_REGION_EMPTY:
		return "Memory region should have at least one page";
	case MANIFEST_ERROR_BASE_ADDRESS_AND_RELATIVE_ADDRESS:
		return "Base and relative addresses are mutually exclusive";
	case MANIFEST_ERROR_MEM_REGION_OVERLAP:
		return "Memory region overlaps with one already allocated";
	case MANIFEST_ERROR_MEM_REGION_UNALIGNED:
		return "Memory region is not aligned to a page boundary";
	case MANIFEST_ERROR_INVALID_MEM_PERM:
		return "Memory permission should be RO, RW or RX";
	case MANIFEST_ERROR_ARGUMENTS_LIST_EMPTY:
		return "Arguments-list node should have at least one argument";
	case MANIFEST_ERROR_INTERRUPT_ID_REPEATED:
		return "Interrupt ID already assigned to another endpoint";
	case MANIFEST_ERROR_ILLEGAL_NS_INT_ACTION:
		return "Illegal value specidied for the field: Action in "
		       "response to NS Interrupt";
	case MANIFEST_ERROR_INTERRUPT_ID_NOT_IN_LIST:
		return "Interrupt ID is not in the list of interrupts";
	case MANIFEST_ERROR_ILLEGAL_OTHER_S_INT_ACTION:
		return "Illegal value specified for the field: Action in "
		       "response to Other-S Interrupt";
	case MANIFEST_ERROR_MEMORY_MISSING:
		return "Memory nodes must be defined in the SPMC manifest "
		       "('memory' and 'ns-memory')";
	case MANIFEST_ERROR_PARTITION_ADDRESS_OVERLAP:
		return "Partition's memory [load address: load address + "
		       "memory size[ overlap with other allocated "
		       "regions";
	case MANIFEST_ERROR_MEM_REGION_INVALID:
		return "Invalid memory region range";
	case MANIFEST_ERROR_DEVICE_MEM_REGION_INVALID:
		return "Invalid device memory region range";
	case MANIFEST_ERROR_INVALID_BOOT_ORDER:
		return "Boot order should be a unique value less than "
		       "default largest value";
	case MANIFEST_ERROR_UUID_ALL_ZEROS:
		return "UUID should not be NIL";
	case MANIFEST_ERROR_TOO_MANY_UUIDS:
		return "Manifest specifies more UUIDs than Hafnium has "
		       "statically allocated space for";
	case MANIFEST_ERROR_MISSING_SMMU_ID:
		return "SMMU ID must be specified for the given Stream IDs";
	case MANIFEST_ERROR_MISMATCH_DMA_ACCESS_PERMISSIONS:
		return "DMA device access permissions must match memory region "
		       "attributes";
	case MANIFEST_ERROR_STREAM_IDS_OVERFLOW:
		return "DMA device stream ID count exceeds predefined limit";
	case MANIFEST_ERROR_DMA_ACCESS_PERMISSIONS_OVERFLOW:
		return "DMA access permissions count exceeds predefined limit";
	case MANIFEST_ERROR_DMA_DEVICE_OVERFLOW:
		return "Number of device regions with DMA peripheral exceeds "
		       "limit.";
	case MANIFEST_ERROR_VM_AVAILABILITY_MESSAGE_INVALID:
		return "VM availability messages invalid (bits [31:2] must be "
		       "zero)";
	}

	panic("Unexpected manifest return code.");
}
