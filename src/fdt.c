/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/fdt.h"

#include <libfdt.h>

#include "hf/static_assert.h"

/** Returns pointer to the FDT buffer. */
const void *fdt_base(const struct fdt *fdt)
{
	return memiter_base(&fdt->buf);
}

/** Returns size of the FDT buffer. */
size_t fdt_size(const struct fdt *fdt)
{
	return memiter_size(&fdt->buf);
}

/**
 * Extracts total size of the FDT structure from its FDT header.
 * Returns true on success, false if header validation failed.
 */
bool fdt_size_from_header(const void *ptr, size_t *val)
{
	if (fdt_check_header(ptr) != 0) {
		return false;
	}

	*val = fdt_totalsize(ptr);
	return true;
}

/**
 * Initializes `struct fdt` to point to a given buffer.
 * Returns true on success, false if FDT validation failed.
 */
bool fdt_init_from_ptr(struct fdt *fdt, const void *ptr, size_t len)
{
	if (fdt_check_full(ptr, len) != 0) {
		return false;
	}

	memiter_init(&fdt->buf, ptr, len);
	return true;
}

/**
 * Initializes `struct fdt` to point to a given buffer.
 * Returns true on success, false if FDT validation failed.
 */
bool fdt_init_from_memiter(struct fdt *fdt, const struct memiter *it)
{
	return fdt_init_from_ptr(fdt, memiter_base(it), memiter_size(it));
}

/**
 * Invalidates the internal pointer to FDT buffer.
 * This is meant to prevent use-after-free bugs.
 */
void fdt_fini(struct fdt *fdt)
{
	memiter_init(&fdt->buf, NULL, 0);
}

/**
 * Finds a node of a given path in the device tree.
 * Unit addresses of components may be omitted but result is undefined if
 * the path is not unique.
 * Returns true on success, false if not found or an error occurred.
 */
bool fdt_find_node(const struct fdt *fdt, const char *path,
		   struct fdt_node *node)
{
	int offset = fdt_path_offset(fdt_base(fdt), path);

	if (offset < 0) {
		return false;
	}

	*node = (struct fdt_node){.fdt = *fdt, .offset = offset};
	return true;
}

/**
 * Retrieves address size for a bus represented in the device tree.
 * Result is value of '#address-cells' at `node` multiplied by cell size.
 * If '#address-cells' is not found, the default value is 2 cells.
 * Returns true on success, false if an error occurred.
 */
bool fdt_address_size(const struct fdt_node *node, size_t *size)
{
	int s = fdt_address_cells(fdt_base(&node->fdt), node->offset);

	if (s < 0) {
		return false;
	}

	*size = (size_t)s * sizeof(uint32_t);
	return true;
}

/**
 * Retrieves address range size for a bus represented in the device tree.
 * Result is value of '#size-cells' at `node` multiplied by cell size.
 * If '#size-cells' is not found, the default value is 1 cell.
 * Returns true on success, false if an error occurred.
 */
bool fdt_size_size(const struct fdt_node *node, size_t *size)
{
	int s = fdt_size_cells(fdt_base(&node->fdt), node->offset);

	if (s < 0) {
		return false;
	}

	*size = (size_t)s * sizeof(uint32_t);
	return true;
}

/**
 * Retrieves the buffer with value of property `name` at `node`.
 * Returns true on success, false if not found or an error occurred.
 */
bool fdt_read_property(const struct fdt_node *node, const char *name,
		       struct memiter *data)
{
	const void *ptr;
	int lenp;

	ptr = fdt_getprop(fdt_base(&node->fdt), node->offset, name, &lenp);
	if (ptr == NULL) {
		return false;
	}

	CHECK(lenp >= 0);
	memiter_init(data, ptr, (size_t)lenp);
	return true;
}

/**
 * Reads the value of property `name` at `node` as a uint.
 * The size of the uint is inferred from the size of the property's value.
 * Returns true on success, false if property not found or an error occurred.
 */
bool fdt_read_number(const struct fdt_node *node, const char *name,
		     uint64_t *val)
{
	struct memiter data;

	return fdt_read_property(node, name, &data) &&
	       fdt_parse_number(&data, memiter_size(&data), val) &&
	       (memiter_size(&data) == 0);
}

/**
 * Parses a uint of given `size` from the beginning of `data`.
 * On success returns true and advances `data` by `size` bytes.
 * Returns false if `data` is too short or uints of `size` are not supported.
 */
bool fdt_parse_number(struct memiter *data, size_t size, uint64_t *val)
{
	struct memiter data_int;
	struct memiter data_rem;

	data_rem = *data;
	if (!memiter_consume(&data_rem, size, &data_int)) {
		return false;
	}

	switch (size) {
	case sizeof(uint32_t): {
		static_assert(sizeof(uint32_t) == sizeof(fdt32_t),
			      "Size mismatch");
		*val = fdt32_ld((const fdt32_t *)memiter_base(&data_int));
		break;
	}
	case sizeof(uint64_t): {
		static_assert(sizeof(uint64_t) == sizeof(fdt64_t),
			      "Size mismatch");
		*val = fdt64_ld((const fdt64_t *)memiter_base(&data_int));
		break;
	}
	default: {
		return false;
	}
	}

	*data = data_rem;
	return true;
}

/**
 * Finds first direct subnode of `node`.
 * If found, makes `node` point to the subnode and returns true.
 * Returns false if no subnode is found.
 */
bool fdt_first_child(struct fdt_node *node)
{
	int child_off = fdt_first_subnode(fdt_base(&node->fdt), node->offset);

	if (child_off < 0) {
		return false;
	}

	node->offset = child_off;
	return true;
}

/**
 * Finds next sibling node of `node`. Call repeatedly to discover all siblings.
 * If found, makes `node` point to the next sibling node and returns true.
 * Returns false if no next sibling node is found.
 */
bool fdt_next_sibling(struct fdt_node *node)
{
	int sib_off = fdt_next_subnode(fdt_base(&node->fdt), node->offset);

	if (sib_off < 0) {
		return false;
	}

	node->offset = sib_off;
	return true;
}

/**
 * Finds a node named `name` among subnodes of `node`.
 * Returns true if found, false if not found or an error occurred.
 */
bool fdt_find_child(struct fdt_node *node, const struct string *name)
{
	struct fdt_node child = *node;
	const void *base = fdt_base(&node->fdt);

	if (!fdt_first_child(&child)) {
		return false;
	}

	do {
		const char *child_name;
		int lenp;
		struct memiter it;

		child_name = fdt_get_name(base, child.offset, &lenp);
		if (child_name == NULL) {
			/* Error */
			return false;
		}

		CHECK(lenp >= 0);
		memiter_init(&it, child_name, (size_t)lenp);
		if (string_eq(name, &it)) {
			node->offset = child.offset;
			return true;
		}
	} while (fdt_next_sibling(&child));

	/* Not found */
	return false;
}

/**
 * Returns true if `node` has property "compatible" containing a `compat` entry.
 * Returns false if node not compatible or an error occurred.
 */
bool fdt_is_compatible(struct fdt_node *node, const char *compat)
{
	return fdt_node_check_compatible(fdt_base(&node->fdt), node->offset,
					 compat) == 0;
}
