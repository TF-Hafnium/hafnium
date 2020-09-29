/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct fdt_node {
	const struct fdt_header *hdr;
	const char *begin;
	const char *end;
	const char *strs;
};

size_t fdt_header_size(void);
uint32_t fdt_total_size(const struct fdt_header *hdr);
void fdt_dump(const struct fdt_header *hdr);
bool fdt_root_node(struct fdt_node *node, const struct fdt_header *hdr);
bool fdt_find_child(struct fdt_node *node, const char *child);
bool fdt_first_child(struct fdt_node *node, const char **child_name);
bool fdt_next_sibling(struct fdt_node *node, const char **sibling_name);
bool fdt_read_property(const struct fdt_node *node, const char *name,
		       const char **buf, uint32_t *size);
bool fdt_parse_number(const char *data, uint32_t size, uint64_t *value);

void fdt_add_mem_reservation(struct fdt_header *hdr, uint64_t addr,
			     uint64_t len);
