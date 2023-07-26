/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/arch/mm.h"

#include "hf/mm.h"
#include "hf/mpool.h"
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

constexpr size_t TEST_HEAP_SIZE = PAGE_SIZE * 16;
const int TOP_LEVEL = arch_mm_stage2_max_level();
const paddr_t VM_MEM_END = pa_init(0x200'0000'0000);

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
bool mm_vm_is_mapped(struct mm_ptable *t, ipaddr_t ipa)
{
	uint32_t mode;
	return mm_vm_get_mode(t, ipa, ipa_add(ipa, 1), &mode) &&
	       (mode & MM_MODE_INVALID) == 0;
}

/**
 * Get an STL representation of the page table.
 */
std::span<pte_t, MM_PTE_PER_PAGE> get_table(paddr_t pa)
{
	auto table = reinterpret_cast<struct mm_page_table *>(
		ptr_from_va(va_from_pa(pa)));
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
		test_heap = std::make_unique<uint8_t[]>(TEST_HEAP_SIZE);
		mpool_init(&ppool, sizeof(struct mm_page_table));
		mpool_add_chunk(&ppool, test_heap.get(), TEST_HEAP_SIZE);
	}

	std::unique_ptr<uint8_t[]> test_heap;

       protected:
	struct mpool ppool;
};

/**
 * A new table is initially empty.
 */
TEST_F(mm, ptable_init_empty)
{
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Each new concatenated table is initially empty.
 */
TEST_F(mm, ptable_init_concatenated_empty)
{
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Only the first page is mapped with all others left absent.
 */
TEST_F(mm, map_first_page)
{
	constexpr uint32_t mode = 0;
	const paddr_t page_begin = pa_init(0);
	const paddr_t page_end = pa_add(page_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode,
				       &ppool, nullptr));

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
		    Eq(pa_addr(page_begin)));

	mm_vm_fini(&ptable, &ppool);
}

/**
 * The start address is rounded down and the end address is rounded up to page
 * boundaries.
 */
TEST_F(mm, map_round_to_page)
{
	constexpr uint32_t mode = 0;
	const paddr_t map_begin = pa_init(0x200'0000'0000 - PAGE_SIZE + 23);
	const paddr_t map_end = pa_add(map_begin, 268);
	ipaddr_t ipa = ipa_init(-1);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode,
				       &ppool, &ipa));
	EXPECT_THAT(ipa_addr(ipa), Eq(pa_addr(map_begin)));

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

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Map a two page range over the boundary of two tables.
 */
TEST_F(mm, map_across_tables)
{
	constexpr uint32_t mode = 0;
	const paddr_t map_begin = pa_init(0x80'0000'0000 - PAGE_SIZE);
	const paddr_t map_end = pa_add(map_begin, 2 * PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode,
				       &ppool, nullptr));

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
		    Eq(pa_addr(map_begin)));

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
		Eq(pa_addr(pa_add(map_begin, PAGE_SIZE))));

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping all of memory creates blocks at the highest level.
 */
TEST_F(mm, map_all_at_top_level)
{
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
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
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Map all memory then trying to map a page again doesn't introduce a special
 * mapping for that particular page.
 */
TEST_F(mm, map_already_mapped)
{
	constexpr uint32_t mode = 0;
	ipaddr_t ipa = ipa_init(-1);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), pa_init(PAGE_SIZE),
				       mode, &ppool, &ipa));
	EXPECT_THAT(ipa_addr(ipa), Eq(0));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping a reverse range, i.e. the end comes before the start, is treated as
 * an empty range so no mappings are made.
 */
TEST_F(mm, map_reverse_range)
{
	constexpr uint32_t mode = 0;
	ipaddr_t ipa = ipa_init(-1);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0x1234'5678),
				       pa_init(0x5000), mode, &ppool, &ipa));
	EXPECT_THAT(ipa_addr(ipa), Eq(0x1234'5678));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping a reverse range in the same page will map the page because the start
 * of the range is rounded down and the end is rounded up.
 *
 * This serves as a form of documentation of behaviour rather than a
 * requirement. Check whether any code relies on this before changing it.
 */
TEST_F(mm, map_reverse_range_quirk)
{
	constexpr uint32_t mode = 0;
	ipaddr_t ipa = ipa_init(-1);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(20), pa_init(10), mode,
				       &ppool, &ipa));
	EXPECT_THAT(ipa_addr(ipa), Eq(20));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa));
	mm_vm_fini(&ptable, &ppool);
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
	constexpr uint32_t mode = 0;
	ipaddr_t ipa = ipa_init(-1);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(
		&ptable, pa_init(0),
		pa_init(std::numeric_limits<uintpaddr_t>::max()), mode, &ppool,
		&ipa));
	EXPECT_THAT(ipa_addr(ipa), Eq(0));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping a range that goes beyond the available memory clamps to the available
 * range.
 */
TEST_F(mm, map_clamp_to_range)
{
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0),
				       pa_init(0xf32'0000'0000'0000), mode,
				       &ppool, nullptr));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping a range outside of the available memory is ignored and doesn't alter
 * the page tables.
 */
TEST_F(mm, map_ignore_out_of_range)
{
	constexpr uint32_t mode = 0;
	ipaddr_t ipa = ipa_init(-1);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, VM_MEM_END,
				       pa_init(0xf0'0000'0000'0000), mode,
				       &ppool, &ipa));
	EXPECT_THAT(ipa_addr(ipa), Eq(pa_addr(VM_MEM_END)));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Map a single page and then map all of memory which replaces the single page
 * mapping with a higher level block mapping.
 */
TEST_F(mm, map_block_replaces_table)
{
	constexpr uint32_t mode = 0;
	const paddr_t page_begin = pa_init(34567 * PAGE_SIZE);
	const paddr_t page_end = pa_add(page_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Map all memory at the top level, unmapping a page and remapping at a lower
 * level does not result in all memory being mapped at the top level again.
 */
TEST_F(mm, map_does_not_defrag)
{
	constexpr uint32_t mode = 0;
	const paddr_t page_begin = pa_init(12000 * PAGE_SIZE);
	const paddr_t page_end = pa_add(page_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, page_begin, page_end, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode,
				       &ppool, nullptr));
	EXPECT_THAT(get_ptable(ptable),
		    AllOf(SizeIs(4),
			  Each(Each(Truly(std::bind(arch_mm_pte_is_present, _1,
						    TOP_LEVEL)))),
			  Contains(Contains(Truly(std::bind(
				  arch_mm_pte_is_block, _1, TOP_LEVEL)))),
			  Contains(Contains(Truly(std::bind(
				  arch_mm_pte_is_table, _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping with a mode that indicates unmapping results in the addresses being
 * unmapped with absent entries.
 */
TEST_F(mm, map_to_unmap)
{
	constexpr uint32_t mode = 0;
	const paddr_t l0_begin = pa_init(uintpaddr_t(524421) * PAGE_SIZE);
	const paddr_t l0_end = pa_add(l0_begin, 17 * PAGE_SIZE);
	const paddr_t l1_begin = pa_init(3 * mm_entry_size(1));
	const paddr_t l1_end = pa_add(l1_begin, 5 * mm_entry_size(1));
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode, &ppool,
				       nullptr));
	EXPECT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END,
				       MM_MODE_UNMAPPED_MASK, &ppool, nullptr));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/*
 * Preparing and committing an address range works the same as mapping it.
 */
TEST_F(mm, prepare_and_commit_first_page)
{
	constexpr uint32_t mode = 0;
	const paddr_t page_begin = pa_init(0);
	const paddr_t page_end = pa_add(page_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, page_begin, page_end, mode,
					   &ppool));
	mm_vm_identity_commit(&ptable, page_begin, page_end, mode, &ppool,
			      nullptr);

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
		    Eq(pa_addr(page_begin)));

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Disjoint address ranges can be prepared and committed together.
 */
TEST_F(mm, prepare_and_commit_disjoint_regions)
{
	constexpr uint32_t mode = 0;
	const paddr_t first_begin = pa_init(0);
	const paddr_t first_end = pa_add(first_begin, PAGE_SIZE);
	const paddr_t last_begin = pa_init(pa_addr(VM_MEM_END) - PAGE_SIZE);
	const paddr_t last_end = VM_MEM_END;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, first_begin, first_end,
					   mode, &ppool));
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, last_begin, last_end, mode,
					   &ppool));
	mm_vm_identity_commit(&ptable, first_begin, first_end, mode, &ppool,
			      nullptr);
	mm_vm_identity_commit(&ptable, last_begin, last_end, mode, &ppool,
			      nullptr);

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
		Eq(pa_addr(first_begin)));

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
		    Eq(pa_addr(last_begin)));

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Overlapping address ranges can be prepared and committed together.
 */
TEST_F(mm, prepare_and_commit_overlapping_regions)
{
	constexpr uint32_t mode = 0;
	const paddr_t low_begin = pa_init(0x80'0000'0000 - PAGE_SIZE);
	const paddr_t high_begin = pa_add(low_begin, PAGE_SIZE);
	const paddr_t map_end = pa_add(high_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, high_begin, map_end, mode,
					   &ppool));
	ASSERT_TRUE(mm_vm_identity_prepare(&ptable, low_begin, map_end, mode,
					   &ppool));
	mm_vm_identity_commit(&ptable, high_begin, map_end, mode, &ppool,
			      nullptr);
	mm_vm_identity_commit(&ptable, low_begin, map_end, mode, &ppool,
			      nullptr);

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
		    Eq(pa_addr(low_begin)));

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
		Eq(pa_addr(high_begin)));

	mm_vm_fini(&ptable, &ppool);
}

/**
 * If range is not mapped, unmapping has no effect.
 */
TEST_F(mm, unmap_not_mapped)
{
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	EXPECT_TRUE(
		mm_vm_unmap(&ptable, pa_init(12345), pa_init(987652), &ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Unmapping everything should result in an empty page table with no subtables.
 */
TEST_F(mm, unmap_all)
{
	constexpr uint32_t mode = 0;
	const paddr_t l0_begin = pa_init(uintpaddr_t(524421) * PAGE_SIZE);
	const paddr_t l0_end = pa_add(l0_begin, 17 * PAGE_SIZE);
	const paddr_t l1_begin = pa_init(3 * mm_entry_size(1));
	const paddr_t l1_end = pa_add(l1_begin, 5 * mm_entry_size(1));
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode, &ppool,
				       nullptr));
	EXPECT_TRUE(mm_vm_unmap(&ptable, pa_init(0), VM_MEM_END, &ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Unmap range is rounded to the containing pages.
 */
TEST_F(mm, unmap_round_to_page)
{
	constexpr uint32_t mode = 0;
	const paddr_t map_begin = pa_init(0x160'0000'0000 + PAGE_SIZE);
	const paddr_t map_end = pa_add(map_begin, PAGE_SIZE);
	struct mm_ptable ptable;

	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, pa_add(map_begin, 93),
				pa_add(map_begin, 99), &ppool));

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

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Unmap a range that of page mappings that spans multiple concatenated tables.
 */
TEST_F(mm, unmap_across_tables)
{
	constexpr uint32_t mode = 0;
	const paddr_t map_begin = pa_init(0x180'0000'0000 - PAGE_SIZE);
	const paddr_t map_end = pa_add(map_begin, 2 * PAGE_SIZE);
	struct mm_ptable ptable;

	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, map_begin, map_end, &ppool));

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

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Unmapping outside the range of memory had no effect.
 */
TEST_F(mm, unmap_out_of_range)
{
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, VM_MEM_END, pa_init(0x4000'0000'0000),
				&ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Unmapping a reverse range, i.e. the end comes before the start, is treated as
 * an empty range so no change is made.
 */
TEST_F(mm, unmap_reverse_range)
{
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, pa_init(0x80'a000'0000), pa_init(27),
				&ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
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
	constexpr uint32_t mode = 0;
	const paddr_t page_begin = pa_init(0x180'0000'0000);
	const paddr_t page_end = pa_add(page_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, pa_add(page_begin, 100),
				pa_add(page_begin, 50), &ppool));

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

	mm_vm_fini(&ptable, &ppool);
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
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(
		&ptable, pa_init(0),
		pa_init(std::numeric_limits<uintpaddr_t>::max()), &ppool));
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Mapping then unmapping a page does not defrag the table.
 */
TEST_F(mm, unmap_does_not_defrag)
{
	constexpr uint32_t mode = 0;
	const paddr_t l0_begin = pa_init(5555 * PAGE_SIZE);
	const paddr_t l0_end = pa_add(l0_begin, 13 * PAGE_SIZE);
	const paddr_t l1_begin = pa_init(666 * mm_entry_size(1));
	const paddr_t l1_end = pa_add(l1_begin, 5 * mm_entry_size(1));
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l0_begin, l0_end, &ppool));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l1_begin, l1_end, &ppool));
	EXPECT_THAT(get_ptable(ptable),
		    AllOf(SizeIs(4),
			  Not(Each(Each(arch_mm_absent_pte(TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Nothing is mapped in an empty table.
 */
TEST_F(mm, is_mapped_empty)
{
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0)));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0x8123'2344)));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0x1e0'0000'0073)));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Everything is mapped in a full table.
 */
TEST_F(mm, is_mapped_all)
{
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(0)));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(0xf247'a7b3)));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_init(0x1ff'7bfa'983b)));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * A page is mapped for the range [begin, end).
 */
TEST_F(mm, is_mapped_page)
{
	constexpr uint32_t mode = 0;
	const paddr_t page_begin = pa_init(0x100'0000'0000);
	const paddr_t page_end = pa_add(page_begin, PAGE_SIZE);
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, page_begin, page_end, mode,
				       &ppool, nullptr));
	EXPECT_TRUE(mm_vm_is_mapped(&ptable, ipa_from_pa(page_begin)));
	EXPECT_TRUE(
		mm_vm_is_mapped(&ptable, ipa_from_pa(pa_add(page_begin, 127))));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_from_pa(page_end)));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Everything out of range is not mapped.
 */
TEST_F(mm, is_mapped_out_of_range)
{
	constexpr uint32_t mode = 0;
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_from_pa(VM_MEM_END)));
	EXPECT_FALSE(mm_vm_is_mapped(&ptable, ipa_init(0x1000'adb7'8123)));
	EXPECT_FALSE(mm_vm_is_mapped(
		&ptable, ipa_init(std::numeric_limits<uintpaddr_t>::max())));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * The mode of unmapped addresses can be retrieved and is set to invalid,
 * unowned and shared.
 */
TEST_F(mm, get_mode_empty)
{
	constexpr int default_mode =
		MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED;
	struct mm_ptable ptable;
	uint32_t read_mode;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));

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

	mm_vm_fini(&ptable, &ppool);
}

/**
 * Get the mode of a range comprised of individual pages which are either side
 * of a root table boundary.
 */
TEST_F(mm, get_mode_pages_across_tables)
{
	constexpr uint32_t mode = MM_MODE_INVALID | MM_MODE_SHARED;
	const paddr_t map_begin = pa_init(0x180'0000'0000 - PAGE_SIZE);
	const paddr_t map_end = pa_add(map_begin, 2 * PAGE_SIZE);
	struct mm_ptable ptable;
	uint32_t read_mode;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, map_begin, map_end, mode,
				       &ppool, nullptr));

	read_mode = 0;
	EXPECT_TRUE(mm_vm_get_mode(&ptable, ipa_from_pa(map_begin),
				   ipa_from_pa(pa_add(map_begin, PAGE_SIZE)),
				   &read_mode));
	EXPECT_THAT(read_mode, Eq(mode));

	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_init(0),
				    ipa_from_pa(pa_add(map_begin, PAGE_SIZE)),
				    &read_mode));

	read_mode = 0;
	EXPECT_TRUE(mm_vm_get_mode(&ptable, ipa_from_pa(map_begin),
				   ipa_from_pa(map_end), &read_mode));
	EXPECT_THAT(read_mode, Eq(mode));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Anything out of range fail to retrieve the mode.
 */
TEST_F(mm, get_mode_out_of_range)
{
	constexpr uint32_t mode = MM_MODE_UNOWNED;
	struct mm_ptable ptable;
	uint32_t read_mode;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_init(0),
				    ipa_from_pa(pa_add(VM_MEM_END, 1)),
				    &read_mode));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_from_pa(VM_MEM_END),
				    ipa_from_pa(pa_add(VM_MEM_END, 1)),
				    &read_mode));
	EXPECT_FALSE(mm_vm_get_mode(&ptable, ipa_init(0x1'1234'1234'1234),
				    ipa_init(2'0000'0000'0000), &read_mode));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Defragging an entirely empty table has no effect.
 */
TEST_F(mm, defrag_empty)
{
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	mm_vm_defrag(&ptable, &ppool, false);
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Defragging a table with some empty subtables (even nested) results in
 * an empty table.
 */
TEST_F(mm, defrag_empty_subtables)
{
	constexpr uint32_t mode = 0;
	const paddr_t l0_begin = pa_init(120000 * PAGE_SIZE);
	const paddr_t l0_end = pa_add(l0_begin, PAGE_SIZE);
	const paddr_t l1_begin = pa_init(3 * mm_entry_size(1));
	const paddr_t l1_end = pa_add(l1_begin, 5 * mm_entry_size(1));
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l0_begin, l0_end, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, l1_begin, l1_end, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l0_begin, l0_end, &ppool));
	ASSERT_TRUE(mm_vm_unmap(&ptable, l1_begin, l1_end, &ppool));
	mm_vm_defrag(&ptable, &ppool, false);
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&ptable, &ppool);
}

/**
 * Any subtable with all blocks with the same attributes should be replaced
 * with a single block.
 */
TEST_F(mm, defrag_block_subtables)
{
	constexpr uint32_t mode = 0;
	const paddr_t begin = pa_init(39456 * mm_entry_size(1));
	const paddr_t middle = pa_add(begin, 67 * PAGE_SIZE);
	const paddr_t end = pa_add(begin, 4 * mm_entry_size(1));
	struct mm_ptable ptable;
	ASSERT_TRUE(mm_vm_init(&ptable, 0, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, pa_init(0), VM_MEM_END, mode,
				       &ppool, nullptr));
	ASSERT_TRUE(mm_vm_unmap(&ptable, begin, end, &ppool));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, begin, middle, mode, &ppool,
				       nullptr));
	ASSERT_TRUE(mm_vm_identity_map(&ptable, middle, end, mode, &ppool,
				       nullptr));
	mm_vm_defrag(&ptable, &ppool, false);
	EXPECT_THAT(
		get_ptable(ptable),
		AllOf(SizeIs(4), Each(Each(Truly(std::bind(arch_mm_pte_is_block,
							   _1, TOP_LEVEL))))));
	mm_vm_fini(&ptable, &ppool);
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
		all.push_back(get_table(
			pa_add(ptable.root, i * sizeof(struct mm_page_table))));
	}
	return all;
}

} /* namespace mm_test */
