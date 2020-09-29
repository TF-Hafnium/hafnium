/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/fdt_handler.h"

#include "hf/boot_params.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/fdt.h"
#include "hf/layout.h"
#include "hf/mm.h"
#include "hf/std.h"

static bool fdt_read_number(const struct fdt_node *node, const char *name,
			    uint64_t *value)
{
	const char *data;
	uint32_t size;

	if (!fdt_read_property(node, name, &data, &size)) {
		return false;
	}

	switch (size) {
	case sizeof(uint32_t):
	case sizeof(uint64_t):
		CHECK(fdt_parse_number(data, size, value));
		break;

	default:
		return false;
	}

	return true;
}

static bool fdt_write_number(struct fdt_node *node, const char *name,
			     uint64_t value)
{
	const char *data;
	uint32_t size;
	union {
		volatile uint64_t v;
		char a[8];
	} t;

	if (!fdt_read_property(node, name, &data, &size)) {
		return false;
	}

	switch (size) {
	case sizeof(uint32_t):
		*(uint32_t *)data = be32toh(value);
		break;

	case sizeof(uint64_t):
		t.v = be64toh(value);
		memcpy_s((void *)data, size, t.a, sizeof(uint64_t));
		break;

	default:
		return false;
	}

	return true;
}

/**
 * Finds the memory region where initrd is stored.
 */
bool fdt_find_initrd(const struct fdt_node *root, paddr_t *begin, paddr_t *end)
{
	struct fdt_node n = *root;
	uint64_t initrd_begin;
	uint64_t initrd_end;

	if (!fdt_find_child(&n, "chosen")) {
		dlog_error("Unable to find 'chosen'\n");
		return false;
	}

	if (!fdt_read_number(&n, "linux,initrd-start", &initrd_begin)) {
		dlog_error("Unable to read linux,initrd-start\n");
		return false;
	}

	if (!fdt_read_number(&n, "linux,initrd-end", &initrd_end)) {
		dlog_error("Unable to read linux,initrd-end\n");
		return false;
	}

	*begin = pa_init(initrd_begin);
	*end = pa_init(initrd_end);

	return true;
}

bool fdt_find_cpus(const struct fdt_node *root, cpu_id_t *cpu_ids,
		   size_t *cpu_count)
{
	struct fdt_node n = *root;
	const char *name;
	uint64_t address_size;

	*cpu_count = 0;

	if (!fdt_find_child(&n, "cpus")) {
		dlog_error("Unable to find 'cpus'\n");
		return false;
	}

	if (fdt_read_number(&n, "#address-cells", &address_size)) {
		address_size *= sizeof(uint32_t);
	} else {
		address_size = sizeof(uint32_t);
	}

	if (!fdt_first_child(&n, &name)) {
		return false;
	}

	do {
		const char *data;
		uint32_t size;

		if (!fdt_read_property(&n, "device_type", &data, &size) ||
		    size != sizeof("cpu") ||
		    memcmp(data, "cpu", sizeof("cpu")) != 0 ||
		    !fdt_read_property(&n, "reg", &data, &size)) {
			continue;
		}

		/* Get all entries for this CPU. */
		while (size >= address_size) {
			uint64_t value;

			if (*cpu_count >= MAX_CPUS) {
				dlog_error("Found more than %d CPUs\n",
					   MAX_CPUS);
				return false;
			}

			if (!fdt_parse_number(data, address_size, &value)) {
				dlog_error("Could not parse CPU id\n");
				return false;
			}
			cpu_ids[(*cpu_count)++] = value;

			size -= address_size;
			data += address_size;
		}
	} while (fdt_next_sibling(&n, &name));

	return true;
}

bool fdt_find_memory_ranges(const struct fdt_node *root,
			    struct string *device_type,
			    struct mem_range *mem_ranges,
			    size_t *mem_ranges_count, size_t mem_range_limit)
{
	struct fdt_node n = *root;
	const char *name;
	uint64_t address_size;
	uint64_t size_size;
	uint64_t entry_size;
	size_t mem_range_index = 0;

	/* Get the sizes of memory range addresses and sizes. */
	if (fdt_read_number(&n, "#address-cells", &address_size)) {
		address_size *= sizeof(uint32_t);
	} else {
		address_size = sizeof(uint32_t);
	}

	if (fdt_read_number(&n, "#size-cells", &size_size)) {
		size_size *= sizeof(uint32_t);
	} else {
		size_size = sizeof(uint32_t);
	}

	entry_size = address_size + size_size;

	/* Look for nodes with the device_type set to "memory". */
	if (!fdt_first_child(&n, &name)) {
		return false;
	}

	do {
		const char *data;
		uint32_t size;

		if (!fdt_read_property(&n, "device_type", &data, &size) ||
		    strncmp(data, string_data(device_type), STRING_MAX_SIZE) !=
			    0 ||
		    !fdt_read_property(&n, "reg", &data, &size)) {
			continue;
		}

		/* Traverse all memory ranges within this node. */
		while (size >= entry_size) {
			uintpaddr_t addr;
			size_t len;

			CHECK(fdt_parse_number(data, address_size, &addr));
			CHECK(fdt_parse_number(data + address_size, size_size,
					       &len));

			if (mem_range_index < mem_range_limit) {
				mem_ranges[mem_range_index].begin =
					pa_init(addr);
				mem_ranges[mem_range_index].end =
					pa_init(addr + len);
				++mem_range_index;
			} else {
				dlog_error(
					"Found %s range %u in FDT but only %u "
					"supported, ignoring additional range "
					"of size %u.\n",
					string_data(device_type),
					mem_range_index, mem_range_limit, len);
			}

			size -= entry_size;
			data += entry_size;
		}
	} while (fdt_next_sibling(&n, &name));
	*mem_ranges_count = mem_range_index;

	return true;
}

struct fdt_header *fdt_map(struct mm_stage1_locked stage1_locked,
			   paddr_t fdt_addr, struct fdt_node *n,
			   struct mpool *ppool)
{
	struct fdt_header *fdt;

	/* Map the fdt header in. */
	fdt = mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_header_size()), MM_MODE_R,
			      ppool);
	if (!fdt) {
		dlog_error("Unable to map FDT header.\n");
		return NULL;
	}

	if (!fdt_root_node(n, fdt)) {
		dlog_error("FDT failed validation.\n");
		goto fail;
	}

	/* Map the rest of the fdt in. */
	fdt = mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_total_size(fdt)), MM_MODE_R,
			      ppool);
	if (!fdt) {
		dlog_error("Unable to map full FDT.\n");
		goto fail;
	}

	return fdt;

fail:
	mm_unmap(stage1_locked, fdt_addr, pa_add(fdt_addr, fdt_header_size()),
		 ppool);
	return NULL;
}

bool fdt_unmap(struct mm_stage1_locked stage1_locked, struct fdt_header *fdt,
	       struct mpool *ppool)
{
	paddr_t fdt_addr = pa_from_va(va_from_ptr(fdt));

	return mm_unmap(stage1_locked, fdt_addr,
			pa_add(fdt_addr, fdt_total_size(fdt)), ppool);
}

bool fdt_patch(struct mm_stage1_locked stage1_locked, paddr_t fdt_addr,
	       struct boot_params_update *p, struct mpool *ppool)
{
	struct fdt_header *fdt;
	struct fdt_node n;
	bool ret = false;
	size_t i;

	/* Map the fdt header in. */
	fdt = mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_header_size()), MM_MODE_R,
			      ppool);
	if (!fdt) {
		dlog_error("Unable to map FDT header.\n");
		return false;
	}

	if (!fdt_root_node(&n, fdt)) {
		dlog_error("FDT failed validation.\n");
		goto err_unmap_fdt_header;
	}

	/* Map the fdt (+ a page) in r/w mode in preparation for updating it. */
	fdt = mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_total_size(fdt) + PAGE_SIZE),
			      MM_MODE_R | MM_MODE_W, ppool);
	if (!fdt) {
		dlog_error("Unable to map FDT in r/w mode.\n");
		goto err_unmap_fdt_header;
	}

	if (!fdt_find_child(&n, "")) {
		dlog_error("Unable to find FDT root node.\n");
		goto out_unmap_fdt;
	}

	if (!fdt_find_child(&n, "chosen")) {
		dlog_error("Unable to find 'chosen'\n");
		goto out_unmap_fdt;
	}

	/* Patch FDT to point to new ramdisk. */
	if (!fdt_write_number(&n, "linux,initrd-start",
			      pa_addr(p->initrd_begin))) {
		dlog_error("Unable to write linux,initrd-start\n");
		goto out_unmap_fdt;
	}

	if (!fdt_write_number(&n, "linux,initrd-end", pa_addr(p->initrd_end))) {
		dlog_error("Unable to write linux,initrd-end\n");
		goto out_unmap_fdt;
	}

	/*
	 * Patch FDT to reserve hypervisor memory so the primary VM doesn't try
	 * to use it.
	 */
	fdt_add_mem_reservation(
		fdt, pa_addr(layout_text_begin()),
		pa_difference(layout_text_begin(), layout_text_end()));
	fdt_add_mem_reservation(
		fdt, pa_addr(layout_rodata_begin()),
		pa_difference(layout_rodata_begin(), layout_rodata_end()));
	fdt_add_mem_reservation(
		fdt, pa_addr(layout_data_begin()),
		pa_difference(layout_data_begin(), layout_data_end()));

	/* Patch FDT to reserve memory for secondary VMs. */
	for (i = 0; i < p->reserved_ranges_count; ++i) {
		fdt_add_mem_reservation(
			fdt, pa_addr(p->reserved_ranges[i].begin),
			pa_addr(p->reserved_ranges[i].end) -
				pa_addr(p->reserved_ranges[i].begin));
	}

	ret = true;

out_unmap_fdt:
	/* Unmap FDT. */
	if (!mm_unmap(stage1_locked, fdt_addr,
		      pa_add(fdt_addr, fdt_total_size(fdt) + PAGE_SIZE),
		      ppool)) {
		dlog_error("Unable to unmap writable FDT.\n");
		return false;
	}
	return ret;

err_unmap_fdt_header:
	mm_unmap(stage1_locked, fdt_addr, pa_add(fdt_addr, fdt_header_size()),
		 ppool);
	return false;
}
