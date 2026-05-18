/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "gtest/gtest.h"

extern "C" {
#include "hf/bits.h"
}

TEST(bits, is_bit_set)
{
	ASSERT_EQ(IS_BIT_SET(UINT64_C(1) << 63, 63), true);
	ASSERT_EQ(IS_BIT_SET(0, 63), false);
}

TEST(bits, is_bit_unset)
{
	ASSERT_EQ(IS_BIT_UNSET(UINT64_C(1) << 63, 63), false);
	ASSERT_EQ(IS_BIT_UNSET(0, 63), true);
}

TEST(bits, get_bits_mask)
{
	ASSERT_EQ(GET_BITS_MASK(0, 0), 0b0001);
	ASSERT_EQ(GET_BITS_MASK(1, 0), 0b0011);
	ASSERT_EQ(GET_BITS_MASK(2, 0), 0b0111);
	ASSERT_EQ(GET_BITS_MASK(7, 0), 0b1111'1111);
	ASSERT_EQ(GET_BITS_MASK(7, 1), 0b1111'1110);

	ASSERT_EQ(GET_BITS_MASK(63, 0), UINT64_MAX);
	ASSERT_EQ(GET_BITS_MASK(63, 1), UINT64_MAX - 1);
}

TEST(bits, get_bits)
{
	ASSERT_EQ(GET_BITS(0xAF, 3, 0), 0x0F);
	ASSERT_EQ(GET_BITS(0xAF, 7, 4), 0xA0);
	ASSERT_EQ(GET_BITS(0x10, 7, 4), 0x10);
	ASSERT_EQ(GET_BITS(0x0F, 7, 4), 0x00);
}

TEST(bits, any_bits_set)
{
	ASSERT_EQ(ANY_BITS_SET(0x01, 3, 0), true);
	ASSERT_EQ(ANY_BITS_SET(0x00, 3, 0), false);
	ASSERT_EQ(ANY_BITS_SET(0x10, 7, 4), true);
	ASSERT_EQ(ANY_BITS_SET(0x0F, 7, 4), false);
}

TEST(bits, all_bits_set)
{
	ASSERT_EQ(ALL_BITS_SET(0b1111, 3, 0), true);
	ASSERT_EQ(ALL_BITS_SET(0b0111, 3, 0), false);
	ASSERT_EQ(ALL_BITS_SET(0xF0, 7, 4), true);
	ASSERT_EQ(ALL_BITS_SET(0xA0, 7, 4), false);
}

TEST(bits, any_bits_unset)
{
	ASSERT_EQ(ANY_BITS_UNSET(0x00, 3, 0), true);
	ASSERT_EQ(ANY_BITS_UNSET(0x01, 3, 0), true);
	ASSERT_EQ(ANY_BITS_UNSET(0x0F, 3, 0), false);
	ASSERT_EQ(ANY_BITS_UNSET(0xF0, 7, 4), false);
	ASSERT_EQ(ANY_BITS_UNSET(0xA0, 7, 4), true);
}

TEST(bits, all_bits_unset)
{
	ASSERT_EQ(ALL_BITS_UNSET(0x01, 3, 0), false);
	ASSERT_EQ(ALL_BITS_UNSET(0x00, 3, 0), true);
	ASSERT_EQ(ALL_BITS_UNSET(0x10, 7, 4), false);
	ASSERT_EQ(ALL_BITS_UNSET(0x0F, 7, 4), true);
}
