/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/fdt.h"
#include "hf/ffa_partition_manifest.h"
#include "hf/manifest_return_codes.h"
#include "hf/memiter.h"
#include "hf/string.h"

#include "vmapi/hf/ffa.h"

#define TRY(expr)                                            \
	do {                                                 \
		enum manifest_return_code ret_code = (expr); \
		if (ret_code != MANIFEST_SUCCESS) {          \
			return ret_code;                     \
		}                                            \
	} while (0)

enum manifest_return_code read_string(const struct fdt_node *node,
				      const char *property, struct string *out);
enum manifest_return_code read_optional_string(const struct fdt_node *node,
					       const char *property,
					       struct string *out);

struct uint32list_iter {
	struct memiter mem_it;
};

enum manifest_return_code read_uint32list(const struct fdt_node *node,
					  const char *property,
					  struct uint32list_iter *out);
enum manifest_return_code read_optional_uint32list(const struct fdt_node *node,
						   const char *property,
						   struct uint32list_iter *out);

bool uint32list_has_next(const struct uint32list_iter *list);
enum manifest_return_code uint32list_get_next(struct uint32list_iter *list,
					      uint32_t *out);

enum manifest_return_code parse_services(const struct fdt_node *node,
					 struct service *services,
					 uint16_t *service_count,
					 uint16_t manifest_version_minor);
