/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/string.h"
}

namespace
{
TEST(string, valid)
{
	struct string str;
	constexpr const char data[] = "test";

	string_init_empty(&str);
	ASSERT_TRUE(string_is_empty(&str));
	ASSERT_STREQ(string_data(&str), "");

	ASSERT_EQ(string_init(&str, data, sizeof(data)), STRING_SUCCESS);
	ASSERT_FALSE(string_is_empty(&str));
	ASSERT_STRNE(string_data(&str), "");
	ASSERT_STREQ(string_data(&str), "test");
}

TEST(string, data_zero_size)
{
	struct string str;
	constexpr const char data[] = "test";

	ASSERT_EQ(string_init(&str, data, 0), STRING_ERROR_INVALID_INPUT);
}

TEST(string, data_no_null_terminator)
{
	struct string str;
	constexpr const char data[] = {'t', 'e', 's', 't'};

	ASSERT_EQ(string_init(&str, data, sizeof(data)),
		  STRING_ERROR_INVALID_INPUT);
}

TEST(string, data_two_null_terminators)
{
	struct string str;
	constexpr const char data[] = {'\0', 't', 'e', 's', 't', '\0'};

	ASSERT_EQ(string_init(&str, data, sizeof(data)),
		  STRING_ERROR_INVALID_INPUT);
}

} /* namespace */
