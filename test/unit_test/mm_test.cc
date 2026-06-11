/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <cstdint>

#include "hf/addr.h"

#include "gtest/gtest.h"
#include <gmock/gmock.h>

extern "C" {
#include "hf/arch/mm.h"

#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/plat/memory_alloc.h"
}

#include <limits>
#include <memory>
#include <span>
#include <vector>

#include "mm_test.hh"

namespace
{
using namespace ::std::placeholders;

using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Each;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::Truly;

using ::mm_test::get_ptable;

const mm_level_t TOP_LEVEL = arch_mm_stage2_root_level() - 1;
const ipaddr_t VM_MEM_END = ipa_init(0x200'0000'0000);

/**
 * Calculates the size of the address space represented by a page table entry at
 * the given level.
 */
size_t mm_entry_size(int level)
{
	return UINT64_C(1) << (PAGE_BITS + level * PAGE_LEVEL_BITS);
}

/**
 * Checks whether the address is mapped in the address space.
 */
bool mm_vm_is_mapped(struct mm_ptable *ptable, ipaddr_t ipa)
{
	mm_mode_t mode;
	return mm_vm_get_mode(ptable, ipa, ipa_add(ipa, 1), &mode) &&
	       (mode & MM_MODE_INVALID) == 0;
}

/**
 * Get an STL representation of the page table.
 */
std::span<pte_t, MM_PTE_PER_PAGE> get_table(struct mm_page_table *table)
{
	return std::span<pte_t, MM_PTE_PER_PAGE>(table->entries,
						 std::end(table->entries));
}

class mm : public ::testing::Test
{
	void SetUp() override
	{
		/*
		 * TODO: replace with direct use of stdlib allocator so
		 * sanitizers are more effective.
		 */
		ASSERT_TRUE(mm_vm_init(&ptable, 0));
	}

	void TearDown() override
	{
		mm_vm_fini(&ptable);
	}

	std::unique_ptr<uint8_t[]> test_heap;

       protected:
	struct mm_ptable ptable;
};

/**
 * A new table is initially empty.
 */
TEST_F(mm, ptable_init_empty)
{
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Each new concatenated table is initially empty.
 */
TEST_F(mm, ptable_init_concatenated_empty)
{
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Only the first page is mapped with all others left absent.
 */
TEST_F(mm, map_first_page)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(0);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the first page is mapped and nothing else. */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		    Eq(ipa_addr(page_begin)));
}

/**
 * Map the second page of the address space to the first frame of memory.
 */
TEST_F(mm, map_non_identity_simple)
{
	constexpr mm_mode_t mode = 0;
	const paddr_t page_paddr = pa_init(0);
	const ipaddr_t page_begin = ipa_from_pa(pa_add(page_paddr, PAGE_SIZE));
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_map(&ptable, page_begin, page_end, page_paddr, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/*
	 * Check that the second page is mapped to the first frame of memory and
	 * that nothing else is mapped.
	 */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0.front(), arch_mm_absent_pte(TOP_LEVEL - 2));
	EXPECT_THAT(table_l0.subspan(2),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[1], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[1], TOP_LEVEL - 2)),
		    Eq(pa_addr(page_paddr)));
}

/**
 * Check that a non-identity mapping will use large pages when the paddr is
 * appropriately aligned.
 */
TEST_F(mm, test_map_2M_page_paddr_aligned)
{
	constexpr mm_mode_t mode = 0;
	const paddr_t page_paddr = pa_init(mm_entry_size(1));
	const ipaddr_t page_begin = ipa_init(0);
	const ipaddr_t page_end = ipa_add(page_begin, mm_entry_size(1));
	ASSERT_TRUE(mm_vm_map(&ptable, page_begin, page_end, page_paddr, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the first large page is mapped and nothing else. */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l1[0], TOP_LEVEL - 1)),
		    Eq(pa_addr(page_paddr)));
}

/**
 * Check that a non-identity mapping will not use large pages when the paddr is
 * not sufficiently aligned.
 */
TEST_F(mm, test_map_2M_page_paddr_not_aligned)
{
	constexpr mm_mode_t mode = 0;
	const paddr_t page_paddr = pa_init(mm_entry_size(0));
	const ipaddr_t page_begin = ipa_init(0);
	const ipaddr_t page_end = ipa_add(page_begin, mm_entry_size(1));
	ASSERT_TRUE(mm_vm_map(&ptable, page_begin, page_end, page_paddr, mode));

	auto tables = get_ptable(ptable);
	/*
	 * Check that a large page was not created, as the paddr is not aligned
	 * to a 2MB boundary
	 */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		    Eq(pa_addr(page_paddr)));
}

/**
 * The start address is rounded down and the end address is rounded up to page
 * boundaries.
 */
TEST_F(mm, map_round_to_page)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t map_begin = ipa_init(0x200'0000'0000 - PAGE_SIZE + 23);
	const ipaddr_t map_end = ipa_add(map_begin, 268);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the last page is mapped, and nothing else. */
	EXPECT_THAT(std::span(tables).first(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.back();
	EXPECT_THAT(table_l2.first(table_l2.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2.last(1)[0], TOP_LEVEL));

	auto table_l1 = get_table(
		arch_mm_table_from_pte(table_l2.last(1)[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.first(table_l1.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1.last(1)[0], TOP_LEVEL - 1));

	auto table_l0 = get_table(
		arch_mm_table_from_pte(table_l1.last(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0.first(table_l0.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0.last(1)[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0.last(1)[0],
						   TOP_LEVEL - 2)),
		    Eq(0x200'0000'0000 - PAGE_SIZE));
}

/**
 * Map a two page range over the boundary of two tables.
 */
TEST_F(mm, map_across_tables)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t map_begin = ipa_init(0x80'0000'0000 - PAGE_SIZE);
	const ipaddr_t map_end = ipa_add(map_begin, 2 * PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	EXPECT_THAT(std::span(tables).last(2),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check only the last page of the first table is mapped. */
	auto table0_l2 = tables.front();
	EXPECT_THAT(table0_l2.first(table0_l2.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l2.last(1)[0], TOP_LEVEL));

	auto table0_l1 = get_table(
		arch_mm_table_from_pte(table0_l2.last(1)[0], TOP_LEVEL));
	EXPECT_THAT(table0_l1.first(table0_l1.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l1.last(1)[0], TOP_LEVEL - 1));

	auto table0_l0 = get_table(
		arch_mm_table_from_pte(table0_l1.last(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table0_l0.first(table0_l0.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table0_l0.last(1)[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table0_l0.last(1)[0],
						   TOP_LEVEL - 2)),
		    Eq(ipa_addr(map_begin)));

	/* Check only the first page of the second table is mapped. */
	auto table1_l2 = tables[1];
	EXPECT_THAT(table1_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table1_l2[0], TOP_LEVEL));

	auto table1_l1 =
		get_table(arch_mm_table_from_pte(table1_l2[0], TOP_LEVEL));
	EXPECT_THAT(table1_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table1_l1[0], TOP_LEVEL - 1));

	auto table1_l0 =
		get_table(arch_mm_table_from_pte(table1_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table1_l0.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table1_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(
		pa_addr(arch_mm_block_from_pte(table1_l0[0], TOP_LEVEL - 2)),
		Eq(ipa_addr(ipa_add(map_begin, PAGE_SIZE))));
}

/**
 * Non-identity map a two page range over the boundary of two tables.
 */
TEST_F(mm, non_identity_map_across_tables)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t map_begin = ipa_init(0x80'0000'0000 - PAGE_SIZE);
	const ipaddr_t map_end = ipa_add(map_begin, 2 * PAGE_SIZE);
	const paddr_t pa_begin = pa_init(0);
	ASSERT_TRUE(mm_vm_map(&ptable, map_begin, map_end, pa_begin, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	EXPECT_THAT(std::span(tables).last(2),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check only the last page of the first table is mapped. */
	auto table0_l2 = tables.front();
	EXPECT_THAT(table0_l2.first(table0_l2.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l2.last(1)[0], TOP_LEVEL));

	auto table0_l1 = get_table(
		arch_mm_table_from_pte(table0_l2.last(1)[0], TOP_LEVEL));
	EXPECT_THAT(table0_l1.first(table0_l1.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l1.last(1)[0], TOP_LEVEL - 1));

	auto table0_l0 = get_table(
		arch_mm_table_from_pte(table0_l1.last(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table0_l0.first(table0_l0.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table0_l0.last(1)[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table0_l0.last(1)[0],
						   TOP_LEVEL - 2)),
		    Eq(pa_addr(pa_begin)));

	/* Check only the first page of the second table is mapped. */
	auto table1_l2 = tables[1];
	EXPECT_THAT(table1_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table1_l2[0], TOP_LEVEL));

	auto table1_l1 =
		get_table(arch_mm_table_from_pte(table1_l2[0], TOP_LEVEL));
	EXPECT_THAT(table1_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table1_l1[0], TOP_LEVEL - 1));

	auto table1_l0 =
		get_table(arch_mm_table_from_pte(table1_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table1_l0.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table1_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(
		pa_addr(arch_mm_block_from_pte(table1_l0[0], TOP_LEVEL - 2)),
		Eq(pa_addr(pa_add(pa_begin, PAGE_SIZE))));
}

/**
 * Mapping all of memory creates blocks at the highest level.
 */
TEST_F(mm, map_all_at_top_level)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	auto tables = get_ptable(ptable);
	EXPECT_THAT(
		tables,
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	for (uint64_t i = 0; i < tables.size(); ++i) {
		for (uint64_t j = 0; j < MM_PTE_PER_PAGE; ++j) {
			EXPECT_THAT(pa_addr(arch_mm_block_from_pte(tables[i][j],
								   TOP_LEVEL)),
				    Eq((i * mm_entry_size(TOP_LEVEL + 1)) +
				       (j * mm_entry_size(TOP_LEVEL))))
				<< "i=" << i << " j=" << j;
		}
	}
}

/**
 * Map all memory then trying to map a page again doesn't introduce a special
 * mapping for that particular page.
 */
TEST_F(mm, map_already_mapped)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0),
				       ipa_init(PAGE_SIZE), mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Map all memory then try and non-identity map a page. Check that the mapping
 * is rejected and that the page tables are unchanged.
 */
TEST_F(mm, already_mapped_non_identity)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_FALSE(mm_vm_map(&ptable, ipa_init(0), ipa_init(PAGE_SIZE),
			       pa_init(PAGE_SIZE), mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Check that you can remap a subset of an identity-mapped range
 */
TEST_F(mm, remap_partial)
{
	/*
	 * Before:
	 *
	 * The range [0x0, 0x200000) is identity mapped.
	 *
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x0, 0x200000)
	 *     [1] = absent
	 *     [2] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 *
	 * After:
	 *
	 * The range [0x100000, 0x101000) is identity mapped with different
	 * mode. The operation should succeed.
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] => table_l0 {
	 *       [0] = 0x0
	 *       [1] = 0x1000
	 *       [2] = 0x2000
	 *       ...
	 *       [256] = 0x100000 (different mode)
	 *       ...
	 *       [511] = 0x1ff000
	 *     }
	 *   }
	 *   [1] = absent
	 *   ...
	 * }
	 */

	constexpr mm_mode_t mode = MM_MODE_R;
	constexpr mm_mode_t remap_mode = MM_MODE_W;
	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t end = ipa_init(mm_entry_size(1));
	const ipaddr_t remap_begin = ipa_init(mm_entry_size(1) / 2);
	const ipaddr_t remap_end = ipa_add(remap_begin, PAGE_SIZE);

	ASSERT_TRUE(mm_vm_identity_map(&ptable, begin, end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, remap_begin, remap_end,
				       remap_mode));

	mm_mode_t got_mode;
	ASSERT_TRUE(mm_vm_get_mode(&ptable, begin, ipa_add(begin, PAGE_SIZE),
				   &got_mode));
	EXPECT_THAT(got_mode, Eq(mode));
	ASSERT_TRUE(mm_vm_get_mode(&ptable, remap_begin, remap_end, &got_mode));
	EXPECT_THAT(got_mode, Eq(remap_mode));

	auto tables = get_ptable(ptable);

	auto table_l2 = tables.front();
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));

	/* Check the first page */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	ASSERT_EQ(arch_mm_stage2_attrs_to_mode(
			  arch_mm_pte_attrs(table_l0[0], TOP_LEVEL - 2)),
		  mode);

	/* Check the middle page */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[MM_PTE_PER_PAGE / 2],
					 TOP_LEVEL - 2));
	ASSERT_EQ(arch_mm_stage2_attrs_to_mode(arch_mm_pte_attrs(
			  table_l0[MM_PTE_PER_PAGE / 2], TOP_LEVEL - 2)),
		  remap_mode);
}

/**
 * Check that you can remap a subset of an non-identity-mapped range
 */
TEST_F(mm, non_identity_remap)
{
	/*
	 * Before:
	 *
	 * The range [0x0..0x200000) is non_identity mapped.
	 *
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x2000000, 0x400000)
	 *     [1] = absent
	 *     [2] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 *
	 * After:
	 *
	 * The range [0x100000..0x101000) is non-identity mapped with a
	 * different mode. The operation should succeed.
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] => table_l0 {
	 *       [0] = 0x200000
	 *       [1] = 0x201000
	 *       [2] = 0x202000
	 *       ...
	 *       [256] = 0x300000 (different mode)
	 *       ...
	 *       [511] = 0x3ff000
	 *     }
	 *   }
	 *   [1] = absent
	 *   ...
	 * }
	 */

	constexpr mm_mode_t mode = MM_MODE_R;
	constexpr mm_mode_t remap_mode = MM_MODE_W;
	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t end = ipa_init(mm_entry_size(1));
	const ipaddr_t remap_begin = ipa_init(mm_entry_size(1) / 2);
	const ipaddr_t remap_end = ipa_add(remap_begin, PAGE_SIZE);

	ASSERT_TRUE(mm_vm_map(&ptable, begin, end, pa_init(mm_entry_size(1)),
			      mode));
	ASSERT_TRUE(mm_vm_map(&ptable, remap_begin, remap_end,
			      pa_init(mm_entry_size(1) + mm_entry_size(1) / 2),
			      remap_mode));

	mm_mode_t got_mode;
	ASSERT_TRUE(mm_vm_get_mode(&ptable, begin, ipa_add(begin, PAGE_SIZE),
				   &got_mode));
	EXPECT_THAT(got_mode, Eq(mode));
	ASSERT_TRUE(mm_vm_get_mode(&ptable, remap_begin, remap_end, &got_mode));
	EXPECT_THAT(got_mode, Eq(remap_mode));

	auto tables = get_ptable(ptable);

	auto table_l2 = tables.front();
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));

	/* Check the first page */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	ASSERT_EQ(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		  mm_entry_size(1));
	ASSERT_EQ(arch_mm_stage2_attrs_to_mode(
			  arch_mm_pte_attrs(table_l0[0], TOP_LEVEL - 2)),
		  mode);

	/* Check the middle page */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[MM_PTE_PER_PAGE / 2],
					 TOP_LEVEL - 2));
	ASSERT_EQ(pa_addr(arch_mm_block_from_pte(table_l0[MM_PTE_PER_PAGE / 2],
						 TOP_LEVEL - 2)),
		  mm_entry_size(1) + (mm_entry_size(1) / 2));
	ASSERT_EQ(arch_mm_stage2_attrs_to_mode(arch_mm_pte_attrs(
			  table_l0[MM_PTE_PER_PAGE / 2], TOP_LEVEL - 2)),
		  remap_mode);
}

/**
 * Test that you can't overmap a mapping within a large page with a random
 * address.
 */
TEST_F(mm, non_identity_overmap_random)
{
	/*
	 * Before:
	 *
	 * The range [0x0, 0x200000) is non-identity mapped.
	 *
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x200000, 0x400000)
	 *     [1] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 *
	 * After:
	 *
	 * A random page in [0x0, 0x200000) is overmapped with a different
	 * physical address. The operation should fail.
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x200000, 0x400000)
	 *     [1] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 */

	constexpr mm_mode_t mode = MM_MODE_R;
	constexpr mm_mode_t overmap_mode = MM_MODE_W;
	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t end = ipa_init(mm_entry_size(1));
	const paddr_t p_begin = pa_init(mm_entry_size(1));
	const ipaddr_t overmap_begin = ipa_init(173 * PAGE_SIZE);
	const ipaddr_t overmap_end = ipa_add(overmap_begin, PAGE_SIZE);
	const paddr_t overmap_paddr = pa_init(0xA00000);

	ASSERT_TRUE(mm_vm_map(&ptable, begin, end, p_begin, mode));
	ASSERT_FALSE(mm_vm_map(&ptable, overmap_begin, overmap_end,
			       overmap_paddr, overmap_mode));

	mm_mode_t got_mode;
	ASSERT_TRUE(mm_vm_get_mode(&ptable, begin, end, &got_mode));
	EXPECT_THAT(got_mode, Eq(mode));
	ASSERT_TRUE(
		mm_vm_get_mode(&ptable, overmap_begin, overmap_end, &got_mode));
	EXPECT_THAT(got_mode, Eq(mode));

	auto tables = get_ptable(ptable);

	auto table_l2 = tables.front();
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l1[0], TOP_LEVEL - 1)),
		    Eq(pa_addr(p_begin)));
}

/**
 * Test that you can't overmap an existing mapping with a large page when the
 * new subrange mapping doesn't correspond exactly to the existing range already
 * within the page.
 */
TEST_F(mm, non_identity_overmap_shifted)
{
	/*
	 * Before:
	 *
	 * The range [0x0, 0x200000) is non-identity mapped.
	 *
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x200000, 0x400000)
	 *     [1] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 *
	 * After:
	 *
	 * A random page in [0x0..0x200000) is overmapped with a different
	 * physical address in the same large page, but not the right one for
	 * that offset. The operation should fail.
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x200000, 0x400000)
	 *     [1] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 */

	constexpr mm_mode_t mode = MM_MODE_R;
	constexpr mm_mode_t overmap_mode = MM_MODE_W;
	constexpr size_t overmap_page_index = 173;
	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t end = ipa_init(mm_entry_size(1));
	const paddr_t p_begin = pa_init(mm_entry_size(1));
	const ipaddr_t overmap_begin = ipa_init(overmap_page_index * PAGE_SIZE);
	const ipaddr_t overmap_end = ipa_add(overmap_begin, PAGE_SIZE);
	const paddr_t overmap_paddr =
		pa_add(p_begin, (overmap_page_index + 1) * PAGE_SIZE);

	ASSERT_TRUE(mm_vm_map(&ptable, begin, end, p_begin, mode));
	ASSERT_FALSE(mm_vm_map(&ptable, overmap_begin, overmap_end,
			       overmap_paddr, overmap_mode));

	mm_mode_t got_mode;
	ASSERT_TRUE(mm_vm_get_mode(&ptable, begin, end, &got_mode));
	EXPECT_THAT(got_mode, Eq(mode));
	ASSERT_TRUE(
		mm_vm_get_mode(&ptable, overmap_begin, overmap_end, &got_mode));
	EXPECT_THAT(got_mode, Eq(mode));

	auto tables = get_ptable(ptable);

	auto table_l2 = tables.front();
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l1[0], TOP_LEVEL - 1)),
		    Eq(pa_addr(p_begin)));
}

/**
 * Test that the paddr is not permitted to overflow in non-identity mappings.
 */
TEST_F(mm, map_non_identity_paddr_overflows)
{
	constexpr mm_mode_t mode = 0;

	/* End physical address overflows uintptr */
	ASSERT_FALSE(mm_vm_map(&ptable, ipa_init(0), ipa_init(2 * PAGE_SIZE),
			       pa_init(UINTPTR_MAX - PAGE_SIZE), mode));

	/* End physical address overflows ptable_end */
	ASSERT_FALSE(mm_vm_map(&ptable, ipa_init(0), ipa_init(PAGE_SIZE),
			       pa_from_ipa(VM_MEM_END), mode));
}

/**
 * Mapping a reverse range, i.e. the end comes before the start, is treated as
 * an empty range so no mappings are made.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, map_reverse_range_quirk)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0x1234'5678),
				       ipa_init(0x5000), mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Mapping a reverse range in the same page will map the page because the start
 * of the range is rounded down and the end is rounded up.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, map_reverse_range_rounded_quirk)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(
		mm_vm_identity_map(&ptable, ipa_init(20), ipa_init(10), mode));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(20)));
}

/**
 * Mapping a range up to the maximum address causes the range end to wrap to
 * zero as it is rounded up to a page boundary meaning no memory is mapped.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, map_last_address_quirk)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(
		&ptable, ipa_init(0),
		ipa_init(std::numeric_limits<uintpaddr_t>::max()), mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Mapping a range that goes beyond the available memory clamps to the available
 * range.
 */
TEST_F(mm, map_clamp_to_range)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0),
				       ipa_init(0xf32'0000'0000'0000), mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Mapping a range outside of the available memory is ignored and doesn't alter
 * the page tables.
 */
TEST_F(mm, map_ignore_out_of_range)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, VM_MEM_END,
				       ipa_init(0xf0'0000'0000'0000), mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Map a single page and then map all of memory which replaces the single page
 * mapping with a higher level block mapping.
 */
TEST_F(mm, map_block_replaces_table)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(34567 * PAGE_SIZE);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Map a single page as non-identity and then attempt to identity map the entire
 * address space, which fails because we reject overmapping.
 */
TEST_F(mm, cant_overmap_non_identity)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(0);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_map(&ptable, page_begin, page_end,
			      pa_from_ipa(ipa_add(page_begin, PAGE_SIZE)),
			      mode));
	ASSERT_FALSE(
		mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the last three root tables are absent . */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(Truly(
			    std::bind(arch_mm_pte_is_absent, _1, TOP_LEVEL)))));

	auto table_l2 = tables.front();
	EXPECT_THAT(
		table_l2.subspan(1),
		Each(Truly(std::bind(arch_mm_pte_is_absent, _1, TOP_LEVEL))));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(Truly(std::bind(arch_mm_pte_is_absent, _1,
					 TOP_LEVEL - 1))));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0.subspan(1),
		    Each(Truly(std::bind(arch_mm_pte_is_absent, _1,
					 TOP_LEVEL - 2))));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		    Eq(PAGE_SIZE));
}

/**
 * Test that a failing overmap call does not partially succeed and
 * change a susbet of a mapping unless the whole mapping can be changed.
 */
TEST_F(mm, overmap_no_partial_success)
{
	/*
	 * Before:
	 *
	 * The range [0x0, 0x1ff000) is identity mapped.
	 * The range [0x200000, 0x400000) is non-identity mapped
	 * The range [0x400000, 0x5ff000) is identity mapped
	 *
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] => table_l0 = {
	 *       [0] = 0x0
	 *       [1] = 0x1000
	 *       [2] = 0x2000
	 *       ...
	 *       [510] = 0x1fe000
	 *       [511] = absent
	 *     }
	 *     [1] = [0xA00000, 0xC00000)
	 *     [2] => table_l0 = {
	 *       [0] = 0x400000
	 *       [1] = 0x401000
	 *       [2] = 0x402000
	 *       ...
	 *       [510] = 0x5fe000
	 *       [511] = absent
	 *     }
	 *   }
	 * }
	 *
	 * After:
	 *
	 * The range [0x0, 0x600000) is identity mapped. The operation
	 * should fail.
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] => table_l0 = {
	 *       [0] = 0x0
	 *       [1] = 0x1000
	 *       [2] = 0x2000
	 *       ...
	 *       [510] = 0x1fe000
	 *       [511] = absent
	 *     }
	 *     [1] = [0xA00000, 0xC00000)
	 *     [2] => table_l0 = {
	 *       [0] = 0x400000
	 *       [1] = 0x401000
	 *       [2] = 0x402000
	 *       ...
	 *       [510] = 0x5fe000
	 *       [511] = absent
	 *     }
	 *   }
	 * }
	 */

	constexpr mm_mode_t mode = 0;

	/* Map the before state */
	ASSERT_TRUE(mm_vm_identity_map(
		&ptable, ipa_init(0),
		ipa_init(mm_entry_size(1) - mm_entry_size(0)), mode));
	ASSERT_TRUE(mm_vm_map(&ptable, ipa_init(mm_entry_size(1)),
			      ipa_init(2 * mm_entry_size(1)),
			      pa_init(0xA000000), mode));
	ASSERT_TRUE(mm_vm_identity_map(
		&ptable, ipa_init(2 * mm_entry_size(1)),
		ipa_init(3 * mm_entry_size(1) - mm_entry_size(0)), mode));

	/*
	 * Try to overmap with an identity mapping spanning the entire existing
	 * mapping
	 */
	ASSERT_FALSE(mm_vm_identity_map(&ptable, ipa_init(0),
					ipa_init(3 * mm_entry_size(1)), mode));

	auto tables = get_ptable(ptable);
	auto table_l2 = tables.front();
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	/* Check the first level 0 table */
	auto table_l0_0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));

	/* Make sure that the first entry is still mapped to the right address.
	 */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0_0[0], TOP_LEVEL - 2));
	EXPECT_THAT(
		pa_addr(arch_mm_block_from_pte(table_l0_0[0], TOP_LEVEL - 2)),
		Eq(0));

	/*
	 * Make sure the second last entry is still mapped to the right address.
	 */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0_0[MM_PTE_PER_PAGE - 2],
					 TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(
			    table_l0_0[MM_PTE_PER_PAGE - 2], TOP_LEVEL - 2)),
		    Eq(510 * mm_entry_size(0)));

	/*
	 * Make sure the last entry wasn't changed as a result of the failing
	 * overmap.
	 */
	ASSERT_TRUE(arch_mm_pte_is_absent(table_l0_0[MM_PTE_PER_PAGE - 1],
					  TOP_LEVEL - 2));

	/* Check the block */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[1], TOP_LEVEL - 1));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l1[1], TOP_LEVEL - 1)),
		    Eq(0xA000000));

	/* Check the second level 0 table */
	auto table_l0_2 =
		get_table(arch_mm_table_from_pte(table_l1[2], TOP_LEVEL - 1));

	/* Make sure that the first entry is still mapped to the right address.
	 */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0_2[0], TOP_LEVEL - 2));
	EXPECT_THAT(
		pa_addr(arch_mm_block_from_pte(table_l0_2[0], TOP_LEVEL - 2)),
		Eq(mm_entry_size(1) * 2));

	/*
	 * Make sure the second last entry is still mapped to the right address.
	 */
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0_2[MM_PTE_PER_PAGE - 2],
					 TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(
			    table_l0_2[MM_PTE_PER_PAGE - 2], TOP_LEVEL - 2)),
		    Eq(2 * mm_entry_size(1) +
		       (MM_PTE_PER_PAGE - 2) * mm_entry_size(0)));

	/*
	 * Make sure the last entry wasn't changed as a result of the failing
	 * overmap.
	 */
	ASSERT_TRUE(arch_mm_pte_is_absent(table_l0_2[MM_PTE_PER_PAGE - 1],
					  TOP_LEVEL - 2));
}

/**
 * Check that a map will caoalesce empty mappings to create a larger block if
 * possible
 */
TEST_F(mm, map_coalesce_partial_entries)
{
	/*
	 * Before:
	 *
	 * The range [0x200000, 0x202000) is identity mapped.
	 *
	 *
	 * table_l2 => {
	 *   [0] = absent,
	 *   [1] => table_l1 = {
	 *     [0] => table_l0 = {
	 *       [0] = 0x200000
	 *       [1] = 0x201000
	 *       [2] = absent
	 *       ...
	 *     }
	 *     [1] = absent
	 *     [2] = absent
	 *     ...
	 *   }
	 *   [2] = absent
	 *   ...
	 * }
	 *
	 * After:
	 *
	 * The range [0x0, 0x400000) is identity mapped. The operation
	 * should succeed.
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = [0x0..0x200000)
	 *     [1] = [0x200000..0x400000)
	 *     [2] = absent
	 *     ...
	 *   }
	 *   [1] = absent
	 *   [2] = absent
	 *   ...
	 * }
	 */

	constexpr mm_mode_t mode = 0;

	const ipaddr_t identity_begin = ipa_init(mm_entry_size(1));
	const ipaddr_t identity_end =
		ipa_add(identity_begin, 2 * mm_entry_size(0));

	ASSERT_TRUE(mm_vm_identity_map(&ptable, identity_begin, identity_end,
				       mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0),
				       ipa_init(2 * mm_entry_size(1)), mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l1[0], TOP_LEVEL - 1)),
		    Eq(0));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[1], TOP_LEVEL - 1));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l1[1], TOP_LEVEL - 1)),
		    Eq(mm_entry_size(1)));
	EXPECT_THAT(table_l1.subspan(2),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
}

/**
 * Check that an identity mapping will not succeed if there is a colliding
 * non-identity mapping already present.
 */
TEST_F(mm, map_dont_coalesce_table_non_identity)
{
	/*
	 * Before:
	 *
	 * The range [0x200000, 0x202000) is identity mapped.
	 * The range [0x202000, 0x203000) is non-identity mapped
	 *
	 *
	 * table_l2 => {
	 *   [0] = absent,
	 *   [1] => table_l1 = {
	 *     [0] => table_l0 = {
	 *       [0] = 0x200000
	 *       [1] = 0x201000
	 *       [2] = 0xA00000
	 *       ...
	 *     }
	 *     [1] = absent
	 *     [2] = absent
	 *     ...
	 *   }
	 *   [2] = absent
	 *   ...
	 * }
	 *
	 * After:
	 *
	 * The range [0x0, 0x400000) is identity mapped. The operation
	 * should fail.
	 *
	 * table_l2 => {
	 *   [0] = absent,
	 *   [1] => table_l1 = {
	 *     [0] => table_l0 = {
	 *       [0] = 0x200000
	 *       [1] = 0x201000
	 *       [2] = 0xA00000
	 *       ...
	 *     }
	 *     [1] = absent
	 *     [2] = absent
	 *     ...
	 *   }
	 *   [2] = absent
	 *   ...
	 * }
	 */

	constexpr mm_mode_t mode = 0;

	const ipaddr_t identity_begin = ipa_init(mm_entry_size(1));
	const ipaddr_t identity_end =
		ipa_add(identity_begin, 2 * mm_entry_size(0));
	const ipaddr_t non_identity_end =
		ipa_add(identity_end, mm_entry_size(0));
	const paddr_t non_identity_paddr = pa_init(0xA00000);

	ASSERT_TRUE(mm_vm_identity_map(&ptable, identity_begin, identity_end,
				       mode));
	ASSERT_TRUE(mm_vm_map(&ptable, identity_end, non_identity_end,
			      non_identity_paddr, mode));

	ASSERT_FALSE(mm_vm_identity_map(&ptable, ipa_init(0),
					ipa_init(2 * mm_entry_size(1)), mode));

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.front(), arch_mm_absent_pte(TOP_LEVEL - 1));
	EXPECT_THAT(table_l1.subspan(2),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[1], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[1], TOP_LEVEL - 1));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		    Eq(mm_entry_size(1)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[1], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[1], TOP_LEVEL - 2)),
		    Eq(mm_entry_size(1) + mm_entry_size(0)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[2], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[2], TOP_LEVEL - 2)),
		    Eq(pa_addr(non_identity_paddr)));
	EXPECT_THAT(table_l0.subspan(3),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
}

/**
 * Map all memory at the top level, unmapping a page and remapping at a lower
 * level does not result in all memory being mapped at the top level again.
 */
TEST_F(mm, map_does_not_defrag)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(12000 * PAGE_SIZE);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, page_begin, page_end));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode));
	EXPECT_THAT(get_ptable(ptable),
		    AllOf(SizeIs(4),
			  Each(Each(Truly(std::bind(arch_mm_pte_is_present, _1,
						    TOP_LEVEL)))),
			  Contains(Contains(Truly(std::bind(
				  arch_mm_pte_is_block, _1, TOP_LEVEL)))),
			  Contains(Contains(Truly(std::bind(
				  arch_mm_pte_is_table, _1, TOP_LEVEL))))));
}

/**
 * Mapping with a mode that indicates unmapping results in the addresses being
 * unmapped with absent entries.
 */
TEST_F(mm, map_to_unmap)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t l0_begin = ipa_init(uintpaddr_t(524421) * PAGE_SIZE);
	const ipaddr_t l0_end = ipa_add(l0_begin, 17 * PAGE_SIZE);
	const ipaddr_t l1_begin = ipa_init(3 * mm_entry_size(1));
	const ipaddr_t l1_end = ipa_add(l1_begin, 5 * mm_entry_size(1));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode));
	EXPECT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END,
				       MM_MODE_UNMAPPED_MASK));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/*
 * Preparing and committing an address range works the same as mapping it.
 */
TEST_F(mm, prepare_and_commit_first_page)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(0);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(
		mm_vm_identity_prepare(&ptable, page_begin, page_end, mode));
	mm_vm_identity_commit(&ptable, page_begin, page_end, mode);

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the first page is mapped and nothing else. */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		    Eq(ipa_addr(page_begin)));
}

/**
 * Disjoint address ranges can be prepared and committed together.
 */
TEST_F(mm, prepare_and_commit_disjoint_regions)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t first_begin = ipa_init(0);
	const ipaddr_t first_end = ipa_add(first_begin, PAGE_SIZE);
	const ipaddr_t last_begin = ipa_init(ipa_addr(VM_MEM_END) - PAGE_SIZE);
	const ipaddr_t last_end = VM_MEM_END;
	ASSERT_TRUE(
		mm_vm_identity_prepare(&ptable, first_begin, first_end, mode));
	ASSERT_TRUE(
		mm_vm_identity_prepare(&ptable, last_begin, last_end, mode));
	mm_vm_identity_commit(&ptable, first_begin, first_end, mode);
	mm_vm_identity_commit(&ptable, last_begin, last_end, mode);

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the first and last pages are mapped and nothing else. */
	EXPECT_THAT(std::span(tables).subspan(1, 2),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	/* Check the first page. */
	auto table0_l2 = tables.front();
	EXPECT_THAT(table0_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l2[0], TOP_LEVEL));

	auto table0_l1 =
		get_table(arch_mm_table_from_pte(table0_l2[0], TOP_LEVEL));
	EXPECT_THAT(table0_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l1[0], TOP_LEVEL - 1));

	auto table0_l0 =
		get_table(arch_mm_table_from_pte(table0_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table0_l0.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table0_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(
		pa_addr(arch_mm_block_from_pte(table0_l0[0], TOP_LEVEL - 2)),
		Eq(ipa_addr(first_begin)));

	/* Check the last page. */
	auto table3_l2 = tables.back();
	EXPECT_THAT(table3_l2.first(table3_l2.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table3_l2.last(1)[0], TOP_LEVEL));

	auto table3_l1 = get_table(
		arch_mm_table_from_pte(table3_l2.last(1)[0], TOP_LEVEL));
	EXPECT_THAT(table3_l1.first(table3_l1.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table3_l1.last(1)[0], TOP_LEVEL - 1));

	auto table3_l0 = get_table(
		arch_mm_table_from_pte(table3_l1.last(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table3_l0.first(table3_l0.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table3_l0.last(1)[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table3_l0.last(1)[0],
						   TOP_LEVEL - 2)),
		    Eq(ipa_addr(last_begin)));
}

/**
 * Overlapping address ranges can be prepared and committed together.
 */
TEST_F(mm, prepare_and_commit_overlapping_regions)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t low_begin = ipa_init(0x80'0000'0000 - PAGE_SIZE);
	const ipaddr_t high_begin = ipa_add(low_begin, PAGE_SIZE);
	const ipaddr_t map_end = ipa_add(high_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, high_begin, map_end, mode));
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, low_begin, map_end, mode));
	mm_vm_identity_commit(&ptable, high_begin, map_end, mode);
	mm_vm_identity_commit(&ptable, low_begin, map_end, mode);

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	EXPECT_THAT(std::span(tables).last(2),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check only the last page of the first table is mapped. */
	auto table0_l2 = tables.front();
	EXPECT_THAT(table0_l2.first(table0_l2.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l2.last(1)[0], TOP_LEVEL));

	auto table0_l1 = get_table(
		arch_mm_table_from_pte(table0_l2.last(1)[0], TOP_LEVEL));
	EXPECT_THAT(table0_l1.first(table0_l1.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table0_l1.last(1)[0], TOP_LEVEL - 1));

	auto table0_l0 = get_table(
		arch_mm_table_from_pte(table0_l1.last(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table0_l0.first(table0_l0.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table0_l0.last(1)[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table0_l0.last(1)[0],
						   TOP_LEVEL - 2)),
		    Eq(ipa_addr(low_begin)));

	/* Check only the first page of the second table is mapped. */
	auto table1_l2 = tables[1];
	EXPECT_THAT(table1_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table1_l2[0], TOP_LEVEL));

	auto table1_l1 =
		get_table(arch_mm_table_from_pte(table1_l2[0], TOP_LEVEL));
	EXPECT_THAT(table1_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table1_l1[0], TOP_LEVEL - 1));

	auto table1_l0 =
		get_table(arch_mm_table_from_pte(table1_l1[0], TOP_LEVEL - 1));
	EXPECT_THAT(table1_l0.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
	ASSERT_TRUE(arch_mm_pte_is_block(table1_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(
		pa_addr(arch_mm_block_from_pte(table1_l0[0], TOP_LEVEL - 2)),
		Eq(ipa_addr(high_begin)));
}

/**
 * If range is not mapped, unmapping has no effect.
 */
TEST_F(mm, unmap_not_mapped)
{
	EXPECT_TRUE(mm_vm_unmap(&ptable, ipa_init(12345), ipa_init(987652)));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Unmapping everything should result in an empty page table with no subtables.
 */
TEST_F(mm, unmap_all)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t l0_begin = ipa_init(uintpaddr_t(524421) * PAGE_SIZE);
	const ipaddr_t l0_end = ipa_add(l0_begin, 17 * PAGE_SIZE);
	const ipaddr_t l1_begin = ipa_init(3 * mm_entry_size(1));
	const ipaddr_t l1_end = ipa_add(l1_begin, 5 * mm_entry_size(1));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode));
	EXPECT_TRUE(mm_vm_unmap(&ptable, ipa_init(0), VM_MEM_END));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Unmap range is rounded to the containing pages.
 */
TEST_F(mm, unmap_round_to_page)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t map_begin = ipa_init(0x160'0000'0000 + PAGE_SIZE);
	const ipaddr_t map_end = ipa_add(map_begin, PAGE_SIZE);

	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, ipa_add(map_begin, 93),
				ipa_add(map_begin, 99)));

	auto tables = get_ptable(ptable);
	constexpr auto l3_index = 2;

	/* Check all other top level entries are empty... */
	EXPECT_THAT(std::span(tables).first(l3_index),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));
	EXPECT_THAT(std::span(tables).subspan(l3_index + 1),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	/* Except the mapped page which is absent. */
	auto table_l2 = tables[l3_index];
	constexpr auto l2_index = 384;
	EXPECT_THAT(table_l2.first(l2_index),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[l2_index], TOP_LEVEL));
	EXPECT_THAT(table_l2.subspan(l2_index + 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));

	auto table_l1 = get_table(
		arch_mm_table_from_pte(table_l2[l2_index], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1.first(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));

	auto table_l0 = get_table(
		arch_mm_table_from_pte(table_l1.first(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0, Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
}

/**
 * Unmap a range that of page mappings that spans multiple concatenated tables.
 */
TEST_F(mm, unmap_across_tables)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t map_begin = ipa_init(0x180'0000'0000 - PAGE_SIZE);
	const ipaddr_t map_end = ipa_add(map_begin, 2 * PAGE_SIZE);

	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, map_begin, map_end));

	auto tables = get_ptable(ptable);

	/* Check the untouched tables are empty. */
	EXPECT_THAT(std::span(tables).first(2),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	/* Check the last page is explicity marked as absent. */
	auto table2_l2 = tables[2];
	EXPECT_THAT(table2_l2.first(table2_l2.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table2_l2.last(1)[0], TOP_LEVEL));

	auto table2_l1 = get_table(
		arch_mm_table_from_pte(table2_l2.last(1)[0], TOP_LEVEL));
	EXPECT_THAT(table2_l1.first(table2_l1.size() - 1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table2_l1.last(1)[0], TOP_LEVEL - 1));

	auto table2_l0 = get_table(
		arch_mm_table_from_pte(table2_l1.last(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table2_l0, Each(arch_mm_absent_pte(TOP_LEVEL - 2)));

	/* Check the first page is explicitly marked as absent. */
	auto table3_l2 = tables[3];
	ASSERT_TRUE(arch_mm_pte_is_table(table3_l2.first(1)[0], TOP_LEVEL));
	EXPECT_THAT(table3_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));

	auto table3_l1 = get_table(
		arch_mm_table_from_pte(table3_l2.first(1)[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_table(table3_l1.first(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table3_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));

	auto table3_l0 = get_table(
		arch_mm_table_from_pte(table3_l1.first(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table3_l0, Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
}

/**
 * Unmapping outside the range of memory had no effect.
 */
TEST_F(mm, unmap_out_of_range)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_TRUE(
		mm_vm_unmap(&ptable, VM_MEM_END, ipa_init(0x4000'0000'0000)));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Unmapping a reverse range, i.e. the end comes before the start, is treated as
 * an empty range so no change is made.
 */
TEST_F(mm, unmap_reverse_range)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_TRUE(
		mm_vm_unmap(&ptable, ipa_init(0x80'a000'0000), ipa_init(27)));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Unmapping a reverse range in the same page will unmap the page because the
 * start of the range is rounded down and the end is rounded up.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, unmap_reverse_range_quirk)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(0x180'0000'0000);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, ipa_add(page_begin, 100),
				ipa_add(page_begin, 50)));

	auto tables = get_ptable(ptable);
	constexpr auto l3_index = 3;

	/* Check all other top level entries are empty... */
	EXPECT_THAT(std::span(tables).first(l3_index),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	/* Except the mapped page which is absent. */
	auto table_l2 = tables[l3_index];
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2.first(1)[0], TOP_LEVEL));
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));

	auto table_l1 = get_table(
		arch_mm_table_from_pte(table_l2.first(1)[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1.first(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));

	auto table_l0 = get_table(
		arch_mm_table_from_pte(table_l1.first(1)[0], TOP_LEVEL - 1));
	EXPECT_THAT(table_l0, Each(arch_mm_absent_pte(TOP_LEVEL - 2)));
}

/**
 * Unmapping a range up to the maximum address causes the range end to wrap to
 * zero as it is rounded up to a page boundary meaning no change is made.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, unmap_last_address_quirk)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_TRUE(
		mm_vm_unmap(&ptable, ipa_init(0),
			    ipa_init(std::numeric_limits<uintpaddr_t>::max())));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Mapping then unmapping a page does not defrag the table.
 */
TEST_F(mm, unmap_does_not_defrag)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t l0_begin = ipa_init(5555 * PAGE_SIZE);
	const ipaddr_t l0_end = ipa_add(l0_begin, 13 * PAGE_SIZE);
	const ipaddr_t l1_begin = ipa_init(666 * mm_entry_size(1));
	const ipaddr_t l1_end = ipa_add(l1_begin, 5 * mm_entry_size(1));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l0_begin, l0_end));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l1_begin, l1_end));
	EXPECT_THAT(get_ptable(ptable),
		    AllOf(SizeIs(4),
			  Not(Each(Each(arch_mm_absent_pte(TOP_LEVEL))))));
}

/**
 * Nothing is mapped in an empty table.
 */
TEST_F(mm, is_mapped_empty)
{
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0)));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0x8123'2344)));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0x1e0'0000'0073)));
}

/**
 * Everything is mapped in a full table.
 */
TEST_F(mm, is_mapped_all)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(0)));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(0xf247'a7b3)));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(0x1ff'7bfa'983b)));
}

/**
 * A page is mapped for the range [begin, end).
 */
TEST_F(mm, is_mapped_page)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t page_begin = ipa_init(0x100'0000'0000);
	const ipaddr_t page_end = ipa_add(page_begin, PAGE_SIZE);
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, page_begin));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_add(page_begin, 127)));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, page_end));
}

/**
 * Everything out of range is not mapped.
 */
TEST_F(mm, is_mapped_out_of_range)
{
	constexpr mm_mode_t mode = 0;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, VM_MEM_END));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0x1000'adb7'8123)));
	EXPECT_FALSE(mm_vm_is_mapped(
		&ptable, ipa_init(std::numeric_limits<uintpaddr_t>::max())));
}

/**
 * The mode of unmapped addresses can be retrieved and is set to invalid,
 * unowned and shared.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, get_mode_empty_quirk)
{
	constexpr int default_mode =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	mm_mode_t read_mode;

	read_mode = 0;
	EXPECT_TRUE(
		mm_vm_get_mode(&ptable, ipa_init(0), ipa_init(20), &read_mode));
	EXPECT_THAT(read_mode, Eq(default_mode));

	read_mode = 0;
	EXPECT_TRUE(mm_vm_get_mode(&ptable, ipa_init(0x3c97'654d),
				   ipa_init(0x3c97'e000), &read_mode));
	EXPECT_THAT(read_mode, Eq(default_mode));

	read_mode = 0;
	EXPECT_TRUE(mm_vm_get_mode(&ptable, ipa_init(0x5f'ffff'ffff),
				   ipa_init(0x1ff'ffff'ffff), &read_mode));
	EXPECT_THAT(read_mode, Eq(default_mode));
}

/**
 * Get the mode of a range comprised of individual pages which are either side
 * of a root table boundary.
 */
TEST_F(mm, get_mode_pages_across_tables)
{
	constexpr mm_mode_t mode = MM_MODE_INVALID | MM_MODE_SHARED;
	const ipaddr_t map_begin = ipa_init(0x180'0000'0000 - PAGE_SIZE);
	const ipaddr_t map_end = ipa_add(map_begin, 2 * PAGE_SIZE);
	mm_mode_t read_mode;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode));

	read_mode = 0;
	EXPECT_TRUE(mm_vm_get_mode(&ptable, map_begin,
				   ipa_add(map_begin, PAGE_SIZE), &read_mode));
	EXPECT_THAT(read_mode, Eq(mode));

	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_init(0),
				    ipa_add(map_begin, PAGE_SIZE), &read_mode));

	read_mode = 0;
	EXPECT_TRUE(mm_vm_get_mode(&ptable, map_begin, map_end, &read_mode));
	EXPECT_THAT(read_mode, Eq(mode));
}

TEST_F(mm, get_mode_partial)
{
	constexpr mm_mode_t mode0 = MM_MODE_R;
	constexpr mm_mode_t mode1 = MM_MODE_W;
	constexpr mm_mode_t mode2 = MM_MODE_X;

	mm_mode_t ret_mode;

	const ipaddr_t page0_start = ipa_init(0);
	const ipaddr_t page0_end = ipa_init(PAGE_SIZE * 1);
	const ipaddr_t page1_start = ipa_init(PAGE_SIZE * 1);
	const ipaddr_t page1_end = ipa_init(PAGE_SIZE * 2);
	const ipaddr_t page2_start = ipa_init(PAGE_SIZE * 2);
	const ipaddr_t page2_end = ipa_init(PAGE_SIZE * 3);
	ipaddr_t end_ret;

	ASSERT_TRUE(mm_vm_identity_map(&ptable, page0_start, page0_end, mode0));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page1_start, page1_end, mode1));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page2_start, page2_end, mode2));

	EXPECT_TRUE(mm_vm_get_mode(&ptable, page0_start, page0_end, &ret_mode));
	EXPECT_THAT(ret_mode, Eq(mode0));

	EXPECT_TRUE(mm_vm_get_mode(&ptable, page1_start, page1_end, &ret_mode));
	EXPECT_THAT(ret_mode, Eq(mode1));

	EXPECT_TRUE(mm_vm_get_mode(&ptable, page2_start, page2_end, &ret_mode));
	EXPECT_THAT(ret_mode, Eq(mode2));

	EXPECT_FALSE(mm_vm_get_mode(&ptable, page0_start, page2_end, nullptr));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, page0_start, page1_end, nullptr));

	EXPECT_TRUE(mm_vm_get_mode_partial(&ptable, page0_start, page1_end,
					   &ret_mode, &end_ret));
	EXPECT_EQ(ipa_addr(end_ret), ipa_addr(page1_start));
	EXPECT_EQ(ret_mode, mode0);

	EXPECT_TRUE(mm_vm_get_mode_partial(&ptable, page1_start, page2_end,
					   &ret_mode, &end_ret));
	EXPECT_EQ(ipa_addr(end_ret), ipa_addr(page2_start));
	EXPECT_EQ(ret_mode, mode1);

	EXPECT_TRUE(mm_vm_get_mode_partial(&ptable, page2_start,
					   ipa_add(page2_end, 2 * PAGE_SIZE),
					   &ret_mode, &end_ret));
	EXPECT_EQ(ipa_addr(end_ret), ipa_addr(page2_end));
	EXPECT_EQ(ret_mode, mode2);
}

/**
 * Anything out of range fail to retrieve the mode.
 */
TEST_F(mm, get_mode_out_of_range)
{
	constexpr mm_mode_t mode = MM_MODE_UNOWNED;
	mm_mode_t read_mode;
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_init(0),
				    ipa_add(VM_MEM_END, 1), &read_mode));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, VM_MEM_END, ipa_add(VM_MEM_END, 1),
				    &read_mode));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_init(0x1'1234'1234'1234),
				    ipa_init(2'0000'0000'0000), &read_mode));
}

/**
 * Defragging an entirely empty table has no effect.
 */
TEST_F(mm, defrag_empty)
{
	mm_vm_defrag(&ptable, false);
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Defragging a table with some empty subtables (even nested) results in
 * an empty table.
 */
TEST_F(mm, defrag_empty_subtables)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t l0_begin = ipa_init(120000 * PAGE_SIZE);
	const ipaddr_t l0_end = ipa_add(l0_begin, PAGE_SIZE);
	const ipaddr_t l1_begin = ipa_init(3 * mm_entry_size(1));
	const ipaddr_t l1_end = ipa_add(l1_begin, 5 * mm_entry_size(1));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l0_begin, l0_end));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l1_begin, l1_end));
	mm_vm_defrag(&ptable, false);
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
}

/**
 * Any subtable with all blocks with the same attributes should be replaced
 * with a single block.
 */
TEST_F(mm, defrag_block_subtables)
{
	constexpr mm_mode_t mode = 0;
	const ipaddr_t begin = ipa_init(39456 * mm_entry_size(1));
	const ipaddr_t middle = ipa_add(begin, 67 * PAGE_SIZE);
	const ipaddr_t end = ipa_add(begin, 4 * mm_entry_size(1));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, ipa_init(0), VM_MEM_END, mode));
	ASSERT_TRUE(mm_vm_unmap(&ptable, begin, end));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, begin, middle, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, middle, end, mode));
	mm_vm_defrag(&ptable, false);
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
}

/**
 * Any subtable with all blocks with the same attributes should be replaced
 * with a single block, even when they are non-identity mapped.
 */
TEST_F(mm, defrag_block_subtables_non_identity)
{
	constexpr mm_mode_t mode = 0;
	const size_t merged_block_size = mm_entry_size(TOP_LEVEL);
	const size_t half_block_size = merged_block_size / 2;

	/* Construct an address range that spans a second level page table */
	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t middle = ipa_add(begin, half_block_size);
	const ipaddr_t end = ipa_add(middle, half_block_size);

	/*
	 * The address chosen here doesn't really matter, as long as it's
	 * aligned to the top level entry size.
	 */
	const paddr_t p_begin = pa_init(16 * mm_entry_size(TOP_LEVEL));
	const paddr_t p_middle = pa_add(p_begin, half_block_size);

	ASSERT_TRUE(mm_vm_map(&ptable, begin, middle, p_begin, mode));
	ASSERT_TRUE(mm_vm_map(&ptable, middle, end, p_middle, mode));

	/* Check that the first top-level entry is initially a table */
	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));
	auto table_l1 = get_table(
		arch_mm_table_from_pte(get_ptable(ptable).at(0)[0], TOP_LEVEL));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[0], TOP_LEVEL - 1));
	mm_attr_t attr_before_defrag =
		arch_mm_pte_attrs(table_l1[0], TOP_LEVEL - 1);

	mm_vm_defrag(&ptable, false);

	/* Check that the entry is transformed to a block with the correct paddr
	 * after defrag. */
	EXPECT_TRUE(arch_mm_pte_is_block((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));
	EXPECT_EQ(pa_addr(arch_mm_block_from_pte(
			  (pte_t)get_ptable(ptable).at(0)[0], TOP_LEVEL)),
		  pa_addr(p_begin));
	EXPECT_EQ(arch_mm_pte_attrs((pte_t)get_ptable(ptable).at(0)[0],
				    TOP_LEVEL),
		  attr_before_defrag);
}

/**
 * Any subtable with all blocks with the same attributes should be replaced
 * with a single block, even when they are non-identity mapped and invalid.
 */
TEST_F(mm, defrag_invalid_block_subtables_non_identity)
{
	constexpr mm_mode_t mode = MM_MODE_INVALID;
	const size_t merged_block_size = mm_entry_size(TOP_LEVEL);
	const size_t half_block_size = merged_block_size / 2;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t middle = ipa_add(begin, half_block_size);
	const ipaddr_t end = ipa_add(middle, half_block_size);

	/*
	 * The address chosen here doesn't really matter, as long as it's
	 * aligned to the top level entry size.
	 */
	const paddr_t p_begin = pa_init(16 * mm_entry_size(TOP_LEVEL));
	const paddr_t p_middle = pa_add(p_begin, half_block_size);

	ASSERT_TRUE(mm_vm_map(&ptable, begin, middle, p_begin, mode));
	ASSERT_TRUE(mm_vm_map(&ptable, middle, end, p_middle, mode));
	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));

	mm_vm_defrag(&ptable, false);

	EXPECT_TRUE(arch_mm_pte_is_block((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));
	EXPECT_EQ(pa_addr(arch_mm_block_from_pte(
			  (pte_t)get_ptable(ptable).at(0)[0], TOP_LEVEL)),
		  pa_addr(p_begin));
}

/**
 * Check that a range is not coalesced (specifically for invalid blocks) if it
 * is not physically contiguous.
 */
TEST_F(mm, defrag_invalid_non_contig_block_subtables)
{
	constexpr mm_mode_t mode = MM_MODE_INVALID;
	const size_t merged_block_size = mm_entry_size(TOP_LEVEL);
	const size_t half_block_size = merged_block_size / 2;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t middle = ipa_add(begin, half_block_size);
	const ipaddr_t end = ipa_add(middle, half_block_size);

	/*
	 * The address chosen here doesn't really matter.
	 */
	const paddr_t p_begin = pa_init(16 * mm_entry_size(TOP_LEVEL));

	ASSERT_TRUE(mm_vm_map(&ptable, begin, middle, pa_init(0), mode));
	ASSERT_TRUE(mm_vm_map(&ptable, middle, end, p_begin, mode));
	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));

	mm_vm_defrag(&ptable, false);

	EXPECT_FALSE(arch_mm_pte_is_block((pte_t)get_ptable(ptable).at(0)[0],
					  TOP_LEVEL));
}

/**
 * Check that a range is not coalesced if it is not physically contiguous.
 */
TEST_F(mm, defrag_non_contig_block_subtables)
{
	constexpr mm_mode_t mode = MM_MODE_R;
	const size_t merged_block_size = mm_entry_size(TOP_LEVEL);
	const size_t half_block_size = merged_block_size / 2;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t middle = ipa_add(begin, half_block_size);
	const ipaddr_t end = ipa_add(middle, half_block_size);

	/*
	 * The address chosen here doesn't really matter.
	 */
	const paddr_t p_begin = pa_init(16 * mm_entry_size(TOP_LEVEL));

	ASSERT_TRUE(mm_vm_map(&ptable, begin, middle, pa_init(0), mode));
	ASSERT_TRUE(mm_vm_map(&ptable, middle, end, p_begin, mode));
	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));
	mm_vm_defrag(&ptable, false);
	EXPECT_FALSE(arch_mm_pte_is_block((pte_t)get_ptable(ptable).at(0)[0],
					  TOP_LEVEL));
}

/**
 * A contiguous range with a non-identity mapped page in the middle should not
 * be coalesced, because the overall physical mapping is no longer contiguous.
 */
TEST_F(mm, defrag_block_subtables_non_identity_middle)
{
	constexpr mm_mode_t mode = 0;
	const size_t merged_block_size = mm_entry_size(TOP_LEVEL);
	const size_t half_block_size = merged_block_size / 2;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t non_identity_start =
		ipa_add(begin, half_block_size - mm_entry_size(TOP_LEVEL - 1));
	const ipaddr_t non_identity_end =
		ipa_add(non_identity_start, mm_entry_size(TOP_LEVEL - 1));
	const ipaddr_t end = ipa_add(non_identity_end, half_block_size);

	/*
	 * The address chosen here doesn't really matter.
	 */
	const paddr_t p_begin = pa_init(16 * mm_entry_size(TOP_LEVEL));

	/*
	 * The mapping is as follows:
	 *
	 * [begin, non_identity_start) -> [begin, non_identity_start)
	 *
	 * [non_identity_start, non_identity_end] -> [p_begin, p_begin +
	 * mm_entry_size(TOP_LEVEL -1))
	 *
	 * [non_identity_end, end) -> [non_identity_end, end)
	 *
	 * The non-identity mapped page in the middle should prevent the whole
	 * range from being coalesced.
	 */
	ASSERT_TRUE(
		mm_vm_identity_map(&ptable, begin, non_identity_start, mode));
	ASSERT_TRUE(mm_vm_map(&ptable, non_identity_start, non_identity_end,
			      p_begin, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, non_identity_end, end, mode));
	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));

	mm_vm_defrag(&ptable, false);

	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));
	auto table_l1 = get_table(
		arch_mm_table_from_pte(get_ptable(ptable).at(0)[0], TOP_LEVEL));
	size_t index = (half_block_size / mm_entry_size(TOP_LEVEL - 1)) - 1;
	ASSERT_TRUE(arch_mm_pte_is_block(table_l1[index], TOP_LEVEL - 1));
	ASSERT_EQ(
		pa_addr(arch_mm_block_from_pte(table_l1[index], TOP_LEVEL - 1)),
		pa_addr(p_begin));
}

/**
 * Test that defrag doesn't combine a physically contiguous table if the
 * physical addresss range it corresponds to is not aligned to the size of the
 * merged entry.
 */
TEST_F(mm, defrag_2mb_page_unaligned)
{
	constexpr mm_mode_t mode = MM_MODE_R;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t end = ipa_add(begin, mm_entry_size(0) * 512);

	const paddr_t p_begin = pa_init(mm_entry_size(0));

	ASSERT_TRUE(mm_vm_map(&ptable, begin, end, p_begin, mode));
	mm_vm_defrag(&ptable, false);

	auto tables = get_ptable(ptable);
	EXPECT_THAT(tables, SizeIs(4));
	ASSERT_THAT(TOP_LEVEL, Eq(2));

	/* Check that the range wasn't coalesced. */
	EXPECT_THAT(std::span(tables).last(3),
		    Each(Each(arch_mm_absent_pte(TOP_LEVEL))));

	auto table_l2 = tables.front();
	EXPECT_THAT(table_l2.subspan(1), Each(arch_mm_absent_pte(TOP_LEVEL)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l2[0], TOP_LEVEL));

	auto table_l1 =
		get_table(arch_mm_table_from_pte(table_l2[0], TOP_LEVEL));
	EXPECT_THAT(table_l1.subspan(1),
		    Each(arch_mm_absent_pte(TOP_LEVEL - 1)));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[0], TOP_LEVEL - 2));
	EXPECT_THAT(pa_addr(arch_mm_block_from_pte(table_l0[0], TOP_LEVEL - 2)),
		    Eq(pa_addr(p_begin)));
}

/**
 * Make sure that everything works as intended when the first entry
 * of a page table refers to a child table, and all other entries are
 * blocks that could have otherwise been merged.
 */
TEST_F(mm, defrag_table_and_blocks)
{
	constexpr mm_mode_t mode = MM_MODE_R;

	const ipaddr_t table_begin = ipa_init(mm_entry_size(0) * 10);
	const ipaddr_t table_end = ipa_add(table_begin, mm_entry_size(0));

	const ipaddr_t block_begin = ipa_init(mm_entry_size(1));
	const ipaddr_t block_end = ipa_add(block_begin, 511 * mm_entry_size(1));

	/*
	 * table_1 => {
	 *   [0] = table_0 => {
	 * 	   [0] = absent
	 * 	   [1] = absent
	 * 	   ...
	 * 	   [10] = block(0xA000)
	 * 	   [11] = absent
	 * 	   ...
	 * 	   [511] = absent
	 * 	 }
	 *   [1] = block(0x200000)
	 *   [2] = block(0x400000)
	 *	 ...
	 *	 [511] = block (0x3fe00000)
	 * }
	 */

	ASSERT_TRUE(mm_vm_identity_map(&ptable, table_begin, table_end, mode));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, block_begin, block_end, mode));

	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));

	mm_vm_defrag(&ptable, false);

	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));
	auto table_l1 = get_table(
		arch_mm_table_from_pte(get_ptable(ptable).at(0)[0], TOP_LEVEL));

	EXPECT_THAT(table_l1.subspan(1),
		    Each(Truly(std::bind(arch_mm_pte_is_block, _1,
					 TOP_LEVEL - 1))));
	ASSERT_TRUE(arch_mm_pte_is_table(table_l1[0], TOP_LEVEL - 1));

	auto table_l0 =
		get_table(arch_mm_table_from_pte(table_l1[0], TOP_LEVEL - 1));
	ASSERT_TRUE(arch_mm_pte_is_block(table_l0[10], TOP_LEVEL - 2));
	EXPECT_EQ(pa_addr(arch_mm_block_from_pte(table_l0[10], TOP_LEVEL - 2)),
		  10 * mm_entry_size(0));
}

/**
 * Make two adjacent aliased mappings, that is, two distinct virtual address
 * ranges that correspond to the same physical addresses and ensure that both
 * are represented correctly after a defrag operation.
 */
TEST_F(mm, defrag_aliased_range)
{
	constexpr mm_mode_t mode = 0;
	const size_t merged_block_size = mm_entry_size(TOP_LEVEL);
	const size_t half_block_size = merged_block_size / 2;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t middle = ipa_add(begin, half_block_size);
	const ipaddr_t end = ipa_add(middle, half_block_size);

	ASSERT_TRUE(mm_vm_identity_map(&ptable, begin, middle, mode));
	ASSERT_TRUE(mm_vm_map(&ptable, middle, end, pa_init(0), mode));

	mm_vm_defrag(&ptable, false);

	EXPECT_TRUE(arch_mm_pte_is_table((pte_t)get_ptable(ptable).at(0)[0],
					 TOP_LEVEL));

	auto table_l1 = get_table(
		arch_mm_table_from_pte(get_ptable(ptable).at(0)[0], TOP_LEVEL));
	size_t mid_index = (half_block_size / mm_entry_size(TOP_LEVEL - 1));

	for (auto i = 0; i < mid_index; i++) {
		ASSERT_TRUE(arch_mm_pte_is_block(table_l1[i], TOP_LEVEL - 1));
		EXPECT_EQ(pa_addr(arch_mm_block_from_pte(table_l1[i],
							 TOP_LEVEL - 1)),
			  i * mm_entry_size(TOP_LEVEL - 1));

		ASSERT_TRUE(arch_mm_pte_is_block(table_l1[mid_index + i],
						 TOP_LEVEL - 1));
		EXPECT_EQ(pa_addr(arch_mm_block_from_pte(
				  table_l1[mid_index + i], TOP_LEVEL - 1)),
			  i * mm_entry_size(TOP_LEVEL - 1));
	}
}

/**
 * Make sure that get range by mode returns the right physical address for a
 * one-page non-identity mapped region.
 */
TEST_F(mm, get_range_by_mode_non_identity)
{
	constexpr mm_mode_t mode = MM_MODE_R;

	const ipaddr_t begin = ipa_init(0);
	const ipaddr_t end = ipa_init(mm_entry_size(0));
	const paddr_t p_begin = pa_init(mm_entry_size(0));

	ASSERT_TRUE(mm_vm_map(&ptable, begin, end, p_begin, mode));

	paddr_t p_begin_ret, p_end_ret;
	ipaddr_t start_addr = ipa_init(0);
	mm_mode_t ptable_mode;

	ASSERT_TRUE(mm_vm_get_range_by_mode(&ptable, &p_begin_ret, &p_end_ret,
					    mode, &start_addr, &ptable_mode));
	EXPECT_EQ(pa_addr(p_begin_ret), pa_addr(p_begin));
	EXPECT_EQ(pa_addr(p_end_ret),
		  pa_addr(pa_add(p_begin, mm_entry_size(0))));
	EXPECT_EQ(ipa_addr(start_addr), ipa_addr(end));
}

/**
 * Make sure that get range by mode treats virtually contiguous but physically
 * disjoint regions as separate ranges.
 */
TEST_F(mm, get_range_by_mode_non_identity_two_range)
{
	constexpr mm_mode_t mode = MM_MODE_R;

	/*
	 * These are the mappings that will be created:
	 *
	 * [0, 0x1000) -> [0, 0x1000)
	 * [0x1000, 0x2000) -> [0x200000, 0x201000)
	 */

	const ipaddr_t begin1 = ipa_init(0);
	const ipaddr_t end1 = ipa_init(mm_entry_size(0));
	const paddr_t p_begin1 = pa_init(mm_entry_size(0));
	const ipaddr_t begin2 = end1;
	const ipaddr_t end2 = ipa_add(begin2, mm_entry_size(0));
	const paddr_t p_begin2 = pa_init(mm_entry_size(1));

	ASSERT_TRUE(mm_vm_map(&ptable, begin1, end1, p_begin1, mode));
	ASSERT_TRUE(mm_vm_map(&ptable, begin2, end2, p_begin2, mode));

	paddr_t p_begin_ret, p_end_ret;
	ipaddr_t start_addr = ipa_init(0);
	mm_mode_t ptable_mode;

	ASSERT_TRUE(mm_vm_get_range_by_mode(&ptable, &p_begin_ret, &p_end_ret,
					    mode, &start_addr, &ptable_mode));
	EXPECT_EQ(pa_addr(p_begin_ret), pa_addr(p_begin1));
	EXPECT_EQ(pa_addr(p_end_ret),
		  pa_addr(pa_add(p_begin1, mm_entry_size(0))));
	EXPECT_EQ(ipa_addr(start_addr), ipa_addr(end1));

	ASSERT_TRUE(mm_vm_get_range_by_mode(&ptable, &p_begin_ret, &p_end_ret,
					    mode, &start_addr, &ptable_mode));
	EXPECT_EQ(pa_addr(p_begin_ret), pa_addr(p_begin2));
	EXPECT_EQ(pa_addr(p_end_ret),
		  pa_addr(pa_add(p_begin2, mm_entry_size(0))));
	EXPECT_EQ(ipa_addr(start_addr), ipa_addr(end2));
}

/**
 * Make sure that get range by mode works correctly when there is a
 * virtually/physically contiguous memory region that spans multiple
 * page tables and levels of page tables.
 */
TEST_F(mm, get_range_by_mode_multilevel)
{
	constexpr mm_mode_t mode = MM_MODE_R;

	/*
	 * The table looks like this:
	 *
	 * table_l2 => {
	 *   [0] => table_l1 = {
	 *     [0] = absent
	 *     [1] = absent
	 *     [2] = absent
	 *     ...
	 *     [511] = 0x3ff000
	 *   }
	 *   [1] = 0x400000
	 * }
	 */

	const ipaddr_t begin = ipa_init(mm_entry_size(1) - mm_entry_size(0));
	const ipaddr_t end = ipa_init(2 * mm_entry_size(1));
	const paddr_t p_begin =
		pa_init(2 * mm_entry_size(1) - mm_entry_size(0));

	ASSERT_TRUE(mm_vm_map(&ptable, begin, end, p_begin, mode));

	paddr_t p_begin_ret, p_end_ret;
	ipaddr_t start_addr = ipa_init(0);
	mm_mode_t ptable_mode;

	ASSERT_TRUE(mm_vm_get_range_by_mode(&ptable, &p_begin_ret, &p_end_ret,
					    mode, &start_addr, &ptable_mode));
	EXPECT_EQ(pa_addr(p_begin_ret), pa_addr(p_begin));
	EXPECT_EQ(
		pa_addr(p_end_ret),
		pa_addr(pa_add(p_begin, mm_entry_size(1) + mm_entry_size(0))));
	EXPECT_EQ(ipa_addr(start_addr), ipa_addr(end));
}

} /* namespace */

namespace mm_test
{
/**
 * Get an STL representation of the ptable.
 */
std::vector<std::span<pte_t, MM_PTE_PER_PAGE>> get_ptable(
	const struct mm_ptable &ptable)
{
	std::vector<std::span<pte_t, MM_PTE_PER_PAGE>> all;
	const uint8_t root_table_count = arch_mm_stage2_root_table_count();
	for (uint8_t i = 0; i < root_table_count; ++i) {
		all.push_back(get_table(&ptable.root_tables[i]));
	}
	return all;
}

} /* namespace mm_test */
