/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "gtest/gtest.h"

extern "C" {
#include "vmapi/hf/ffa.h"
}

#include <initializer_list>

namespace
{
static ffa_notifications_bitmap_t notification_bitmap_from_ids(
	std::initializer_list<uint32_t> ids)
{
	ffa_notifications_bitmap_t bitmap;

	ffa_notification_bitmap_init(&bitmap);

	for (uint32_t id : ids) {
		ffa_notification_bitmap_set(&bitmap, id);
	}

	return bitmap;
}

TEST(notification_bitmap, initializes_to_zero)
{
	ffa_notifications_bitmap_t bitmap;

	ffa_notification_bitmap_init(&bitmap);

	EXPECT_TRUE(ffa_notification_bitmap_is_zero(bitmap));

	for (uint32_t id = 0; id < MAX_FFA_NOTIFICATIONS; ++id) {
		EXPECT_FALSE(ffa_notification_bitmap_is_set(bitmap, id));
	}
}

TEST(notification_bitmap, sets_and_clears_word_boundaries)
{
	constexpr uint32_t notification_ids[] = {
		0, 63, 64, 127, 128, 191, 192, 255, 256, 319, 320, 383,
	};
	ffa_notifications_bitmap_t bitmap;

	ffa_notification_bitmap_init(&bitmap);

	for (uint32_t id : notification_ids) {
		ffa_notification_bitmap_set(&bitmap, id);
		EXPECT_TRUE(ffa_notification_bitmap_is_set(bitmap, id));
	}

	EXPECT_FALSE(ffa_notification_bitmap_is_zero(bitmap));
	EXPECT_FALSE(ffa_notification_bitmap_is_set(bitmap, 1));
	EXPECT_FALSE(ffa_notification_bitmap_is_set(bitmap, 62));
	EXPECT_FALSE(ffa_notification_bitmap_is_set(bitmap, 65));

	for (uint32_t id : notification_ids) {
		ffa_notification_bitmap_clear(&bitmap, id);
		EXPECT_FALSE(ffa_notification_bitmap_is_set(bitmap, id));
	}

	EXPECT_TRUE(ffa_notification_bitmap_is_zero(bitmap));
}

TEST(notification_bitmap, converts_to_and_from_registers)
{
	const uint64_t expected_x3 = UINT64_C(0x0123456789abcdef);
	const uint64_t expected_x4 = UINT64_C(0x1111222233334444);
	const uint64_t expected_x5 = UINT64_C(0x5555666677778888);
	const uint64_t expected_x6 = UINT64_C(0x9999aaaabbbbcccc);
	const uint64_t expected_x7 = UINT64_C(0xddddeeeeffff0000);
	const uint64_t expected_x8 = UINT64_C(0xfedcba9876543210);
	uint64_t x3;
	uint64_t x4;
	uint64_t x5;
	uint64_t x6;
	uint64_t x7;
	uint64_t x8;

	const ffa_notifications_bitmap_t bitmap =
		ffa_notification_bitmap_from_regs(expected_x3, expected_x4,
						  expected_x5, expected_x6,
						  expected_x7, expected_x8);

	ffa_notification_bitmap_to_regs(bitmap, &x3, &x4, &x5, &x6, &x7, &x8);

	EXPECT_EQ(x3, expected_x3);
	EXPECT_EQ(x4, expected_x4);
	EXPECT_EQ(x5, expected_x5);
	EXPECT_EQ(x6, expected_x6);
	EXPECT_EQ(x7, expected_x7);
	EXPECT_EQ(x8, expected_x8);
}

TEST(notification_bitmap, converts_legacy_u64)
{
	const uint64_t legacy_64 = UINT64_C(0xabcdef9876543210);
	const ffa_notifications_bitmap_t expected =
		ffa_notification_bitmap_from_regs(legacy_64, 0, 0, 0, 0, 0);
	const ffa_notifications_bitmap_t bitmap =
		ffa_notification_bitmap_from_legacy_u64(legacy_64);

	EXPECT_TRUE(ffa_notification_bitmap_equal(bitmap, expected));
	EXPECT_EQ(ffa_notification_bitmap_low64(bitmap), legacy_64);
	EXPECT_EQ(ffa_notification_bitmap_low32(bitmap), UINT32_C(0x76543210));
	EXPECT_EQ(ffa_notification_bitmap_high32(bitmap), UINT32_C(0xabcdef98));
}

TEST(notification_bitmap, performs_bitwise_operations)
{
	const ffa_notifications_bitmap_t left =
		notification_bitmap_from_ids({0, 64, 383});
	const ffa_notifications_bitmap_t right =
		notification_bitmap_from_ids({64, 127});
	const ffa_notifications_bitmap_t disjoint =
		notification_bitmap_from_ids({1, 65});

	const ffa_notifications_bitmap_t expected_or =
		notification_bitmap_from_ids({0, 64, 127, 383});
	const ffa_notifications_bitmap_t expected_and =
		notification_bitmap_from_ids({64});
	const ffa_notifications_bitmap_t expected_and_not =
		notification_bitmap_from_ids({0, 383});

	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_or(left, right), expected_or));
	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_and(left, right), expected_and));
	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_exclude(left, right),
		expected_and_not));

	EXPECT_TRUE(ffa_notification_bitmap_intersects(left, right));
	EXPECT_FALSE(ffa_notification_bitmap_intersects(left, disjoint));
	EXPECT_TRUE(ffa_notification_bitmap_equal(left, left));
	EXPECT_FALSE(ffa_notification_bitmap_equal(left, right));
}

TEST(notification_bitmap, extracts_bitmaps_from_ffa_value)
{
	struct ffa_value args = {};

	args.arg3 = UINT64_C(3);
	args.arg4 = UINT64_C(4);
	args.arg5 = UINT64_C(5);
	args.arg6 = UINT64_C(6);
	args.arg7 = UINT64_C(7);
	args.extended_val.arg8 = UINT64_C(8);
	args.extended_val.arg9 = UINT64_C(9);
	args.extended_val.arg10 = UINT64_C(10);
	args.extended_val.arg11 = UINT64_C(11);
	args.extended_val.arg12 = UINT64_C(12);
	args.extended_val.arg13 = UINT64_C(13);
	args.extended_val.arg14 = UINT64_C(14);

	const ffa_notifications_bitmap_t expected_x3_x8 =
		ffa_notification_bitmap_from_regs(3, 4, 5, 6, 7, 8);
	const ffa_notifications_bitmap_t expected_x9_x14 =
		ffa_notification_bitmap_from_regs(9, 10, 11, 12, 13, 14);

	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_from_x3_x8(args), expected_x3_x8));
	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_from_x9_x14(args), expected_x9_x14));
	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_from_get2_sp(args), expected_x3_x8));
	EXPECT_TRUE(ffa_notification_bitmap_equal(
		ffa_notification_bitmap_from_get2_vm(args), expected_x9_x14));
}

} /* namespace */
