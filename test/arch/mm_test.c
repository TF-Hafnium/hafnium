/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mm.h"

#include "hf/arch/mm.h"

#include "test/hftest.h"

/** There must be at least two levels in the page table. */
#define ROOT_LEVEL_LOWER_BOUND 2

/**
 * This is the number of levels that are tested and is constrained as it
 * controls the depth of recursion in the memory management code.
 */
#define ROOT_LEVEL_UPPER_BOUND 4

/* TODO: work out how to run these test against the host fake arch. */

/**
 * A block must be allowed at level 0 as this is the level which represents
 * pages.
 */
TEST(arch_mm, block_allowed_at_level0)
{
	ASSERT_TRUE(arch_mm_is_block_allowed(0));
}

/**
 * The root level must be within acceptable bounds.
 */
TEST(arch_mm, root_level_stage1)
{
	uint32_t pa_bits = arch_mm_get_pa_bits(arch_mm_get_pa_range());
	mm_attr_t root_level;

	arch_mm_stage1_root_level_set(pa_bits);
	root_level = arch_mm_stage1_root_level();

	EXPECT_GE(root_level, ROOT_LEVEL_LOWER_BOUND);
	EXPECT_LE(root_level, ROOT_LEVEL_UPPER_BOUND);
}

/* TODO: initialize arch_mm and check max level of stage-2. */

/**
 * An absent entry is not present, valid, a block nor a table.
 */
TEST(arch_mm, absent_properties)
{
	for (mm_level_t level = 0; level <= ROOT_LEVEL_UPPER_BOUND; level++) {
		pte_t absent_pte;

		absent_pte = arch_mm_absent_pte(level);

		EXPECT_EQ(arch_mm_pte_type(absent_pte, level), PTE_TYPE_ABSENT);
		EXPECT_FALSE(arch_mm_pte_is_present(absent_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_valid(absent_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_block(absent_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_table(absent_pte, level));
	}
}

/**
 * An invalid block is present and mutually exclusive from a table.
 */
TEST(arch_mm, invalid_block_properties)
{
	for (mm_level_t level = 0; level <= ROOT_LEVEL_UPPER_BOUND; level++) {
		mm_attr_t attrs = arch_mm_mode_to_stage2_attrs(MM_MODE_INVALID);
		pte_t block_pte;

		/* Test doesn't apply if a block is not allowed. */
		if (!arch_mm_is_block_allowed(level)) {
			continue;
		}

		block_pte = arch_mm_block_pte(level, pa_init(PAGE_SIZE * 19),
					      attrs);

		EXPECT_EQ(arch_mm_pte_type(block_pte, level),
			  PTE_TYPE_INVALID_BLOCK);
		EXPECT_TRUE(arch_mm_pte_is_present(block_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_valid(block_pte, level));
		EXPECT_TRUE(arch_mm_pte_is_block(block_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_table(block_pte, level));
	}
}

/**
 * A valid block is present and mutually exclusive from a table.
 */
TEST(arch_mm, valid_block_properties)
{
	for (mm_level_t level = 0; level <= ROOT_LEVEL_UPPER_BOUND; level++) {
		mm_attr_t attrs = arch_mm_mode_to_stage2_attrs(0);
		pte_t block_pte;

		/* Test doesn't apply if a block is not allowed. */
		if (!arch_mm_is_block_allowed(level)) {
			continue;
		}

		block_pte = arch_mm_block_pte(
			level, pa_init(PAGE_SIZE * 12345678U), attrs);

		EXPECT_EQ(arch_mm_pte_type(block_pte, level),
			  PTE_TYPE_VALID_BLOCK);
		EXPECT_TRUE(arch_mm_pte_is_present(block_pte, level));
		EXPECT_TRUE(arch_mm_pte_is_valid(block_pte, level));
		EXPECT_TRUE(arch_mm_pte_is_block(block_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_table(block_pte, level));
	}
}

/**
 * A table is present, valid and mutually exclusive from a block.
 */
TEST(arch_mm, table_properties)
{
	for (mm_level_t level = 0; level <= ROOT_LEVEL_UPPER_BOUND; level++) {
		pte_t table_pte;

		/* Test doesn't apply to level 0 as there can't be a table. */
		if (level == 0) {
			continue;
		}

		table_pte = arch_mm_table_pte(level,
					      pa_init(PAGE_SIZE * 999999999U));

		EXPECT_EQ(arch_mm_pte_type(table_pte, level), PTE_TYPE_TABLE);
		EXPECT_TRUE(arch_mm_pte_is_present(table_pte, level));
		EXPECT_TRUE(arch_mm_pte_is_valid(table_pte, level));
		EXPECT_FALSE(arch_mm_pte_is_block(table_pte, level));
		EXPECT_TRUE(arch_mm_pte_is_table(table_pte, level));
	}
}

/**
 * The address and attributes of a block must be preserved when encoding and
 * decoding.
 */
TEST(arch_mm, block_addr_and_attrs_preserved)
{
	for (mm_level_t level = 0; level <= ROOT_LEVEL_UPPER_BOUND; level++) {
		paddr_t addr;
		mm_attr_t attrs;
		pte_t block_pte;

		/* Test doesn't apply if a block is not allowed. */
		if (!arch_mm_is_block_allowed(level)) {
			continue;
		}

		addr = pa_init(0);
		attrs = arch_mm_mode_to_stage2_attrs(0);
		block_pte = arch_mm_block_pte(level, addr, attrs);
		EXPECT_EQ(arch_mm_pte_attrs(block_pte, level), attrs);
		EXPECT_EQ(pa_addr(arch_mm_block_from_pte(block_pte, level)),
			  pa_addr(addr));

		addr = pa_init(PAGE_SIZE * 17);
		attrs = arch_mm_mode_to_stage2_attrs(MM_MODE_INVALID);
		block_pte = arch_mm_block_pte(level, addr, attrs);
		EXPECT_EQ(arch_mm_pte_attrs(block_pte, level), attrs);
		EXPECT_EQ(pa_addr(arch_mm_block_from_pte(block_pte, level)),
			  pa_addr(addr));

		addr = pa_init(PAGE_SIZE * 500);
		attrs = arch_mm_mode_to_stage2_attrs(MM_MODE_R | MM_MODE_W);
		block_pte = arch_mm_block_pte(level, addr, attrs);
		EXPECT_EQ(arch_mm_pte_attrs(block_pte, level), attrs);
		EXPECT_EQ(pa_addr(arch_mm_block_from_pte(block_pte, level)),
			  pa_addr(addr));
	}
}
