/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/memiter.h"
#include "hf/string.h"

/**
 * Wrapper around a pointer to a Flattened Device Tree (FDT) structure located
 * somewhere in mapped main memory. Sanity checks are performed on initilization
 * to ensure it is pointing to a valid FDT and most libfdt API calls check for
 * the presence of the FDT magic.
 */
struct fdt {
	struct memiter buf;
};

/**
 * Wrapper around a pointer to a valid Device Tree node inside a FDT structure.
 */
struct fdt_node {
	struct fdt fdt;
	int offset;
};

#define FDT_V17_HEADER_SIZE (10 * sizeof(uint32_t))

bool fdt_size_from_header(const void *ptr, size_t *val);

bool fdt_init_from_ptr(struct fdt *fdt, const void *ptr, size_t len);
bool fdt_init_from_memiter(struct fdt *fdt, const struct memiter *it);
void fdt_fini(struct fdt *fdt);

const void *fdt_base(const struct fdt *fdt);
size_t fdt_size(const struct fdt *fdt);

bool fdt_find_node(const struct fdt *fdt, const char *path,
		   struct fdt_node *node);
bool fdt_is_compatible(struct fdt_node *node, const char *compat);
bool fdt_address_size(const struct fdt_node *node, size_t *addr_size);
bool fdt_size_size(const struct fdt_node *node, size_t *size);

bool fdt_first_child(struct fdt_node *node);
bool fdt_next_sibling(struct fdt_node *node);
bool fdt_find_child(struct fdt_node *node, const struct string *name);

bool fdt_read_property(const struct fdt_node *node, const char *name,
		       struct memiter *data);
bool fdt_read_number(const struct fdt_node *node, const char *name,
		     uint64_t *val);
bool fdt_parse_number(struct memiter *data, size_t size, uint64_t *val);
