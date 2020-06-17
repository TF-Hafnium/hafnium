/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/string.h"

#include "hf/static_assert.h"
#include "hf/std.h"

void string_init_empty(struct string *str)
{
	static_assert(sizeof(str->data) >= 1, "String buffer too small");
	str->data[0] = '\0';
}

/**
 * Caller must guarantee that `data` points to a NULL-terminated string.
 * The constructor checks that it fits into the internal buffer and copies
 * the string there.
 */
enum string_return_code string_init(struct string *str,
				    const struct memiter *data)
{
	const char *base = memiter_base(data);
	size_t size = memiter_size(data);

	/*
	 * Require that the value contains exactly one NULL character and that
	 * it is the last byte.
	 */
	if (size < 1 || memchr(base, '\0', size) != &base[size - 1]) {
		return STRING_ERROR_INVALID_INPUT;
	}

	if (size > sizeof(str->data)) {
		return STRING_ERROR_TOO_LONG;
	}

	memcpy_s(str->data, sizeof(str->data), base, size);
	return STRING_SUCCESS;
}

bool string_is_empty(const struct string *str)
{
	return str->data[0] == '\0';
}

const char *string_data(const struct string *str)
{
	return str->data;
}

/**
 * Returns true if the iterator `data` contains string `str`.
 * Only characters until the first null terminator are compared.
 */
bool string_eq(const struct string *str, const struct memiter *data)
{
	const char *base = memiter_base(data);
	size_t len = memiter_size(data);

	return (len <= sizeof(str->data)) &&
	       (strncmp(str->data, base, len) == 0);
}
