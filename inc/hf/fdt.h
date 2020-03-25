/*
 * Copyright 2018 The Hafnium Authors.
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
