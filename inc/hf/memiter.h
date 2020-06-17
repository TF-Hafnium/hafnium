/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct memiter {
	const char *next;
	const char *limit;
};

void memiter_init(struct memiter *it, const void *data, size_t size);
bool memiter_parse_uint(struct memiter *it, uint64_t *value);
bool memiter_parse_str(struct memiter *it, struct memiter *str);
bool memiter_iseq(const struct memiter *it, const char *str);
bool memiter_advance(struct memiter *it, size_t v);
bool memiter_restrict(struct memiter *it, size_t v);
bool memiter_consume(struct memiter *it, size_t v, struct memiter *newit);

const void *memiter_base(const struct memiter *it);
size_t memiter_size(const struct memiter *it);
