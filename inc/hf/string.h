/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "hf/memiter.h"

/**
 * Maximum length of a string including the NULL terminator.
 * This is an arbitrary number and can be adjusted to fit use cases.
 */
#define STRING_MAX_SIZE 32

enum string_return_code {
	STRING_SUCCESS,
	STRING_ERROR_INVALID_INPUT,
	STRING_ERROR_TOO_LONG,
};

/**
 * Statically-allocated string data structure with input validation to ensure
 * strings are properly NULL-terminated.
 *
 * This is intentionally kept as simple as possible and should not be extended
 * to perform complex string operations without a good use case.
 */
struct string {
	char data[STRING_MAX_SIZE];
};

/**
 * Macro to initialize `struct string` from a string constant.
 * Triggers a compilation error if the string does not fit into the buffer.
 */
#define STRING_INIT(str) ((struct string){.data = (str)})

enum string_return_code string_init(struct string *str,
				    const struct memiter *data);
void string_init_empty(struct string *str);
bool string_is_empty(const struct string *str);
const char *string_data(const struct string *str);
bool string_eq(const struct string *str, const struct memiter *data);
