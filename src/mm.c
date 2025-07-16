/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mm.h"

#include <stdatomic.h>
#include <stdint.h>

#include "hf/arch/init.h"
#include "hf/arch/mm.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/layout.h"
#include "hf/plat/console.h"
#include "hf/plat/memory_alloc.h"
#include "hf/std.h"

/*
 * TODO: Intermediate step to drop the dependency to mpool and use
 * memory allocator abstraction first.
 */
static struct mpool *ppool;

/**
 * This file has functions for managing the level 1 and 2 page tables used by
 * Hafnium. There is a level 1 mapping used by Hafnium itself to access memory,
 * and then a level 2 mapping per VM. The design assumes that all page tables
 * contain only 1-1 mappings, aligned on the block boundaries.
 */

/*
 * For stage 2, the input is an intermediate physical addresses rather than a
 * virtual address so:
 */
static_assert(
	sizeof(ptable_addr_t) == sizeof(uintpaddr_t),
	"Currently, the same code manages the stage 1 and stage 2 page tables "
	"which only works if the virtual and intermediate physical addresses "
	"are the same size. It looks like that assumption might not be holding "
	"so we need to check that everything is going to be ok.");

static struct mm_ptable ptable;
static struct spinlock ptable_lock;

static bool mm_stage2_invalidate = false;

/**
 * After calling this function, modifications to stage-2 page tables will use
 * break-before-make and invalidate the TLB for the affected range.
 */
void mm_vm_enable_invalidation(void)
{
	mm_stage2_invalidate = true;
}

/**
 * Rounds an address down to a page boundary.
 */
static ptable_addr_t mm_round_down_to_page(ptable_addr_t addr)
{
	return align_down(addr, PAGE_SIZE);
}

/**
 * Rounds an address up to a page boundary.
 */
static ptable_addr_t mm_round_up_to_page(ptable_addr_t addr)
{
	return align_up(addr, PAGE_SIZE);
}

/**
 * Calculates the size of the address space represented by a page table entry at
 * the given level. See also Arm ARM, table D8-15
 * - `level == 4`: 256 TiB (1 << 48)
 * - `level == 3`: 512 GiB (1 << 39)
 * - `level == 2`:   1 GiB (1 << 30)
 * - `level == 1`:   2 MiB (1 << 21)
 * - `level == 0`:   4 KiB (1 << 12)
 */
static size_t mm_entry_size(mm_level_t level)
{
	assert(level <= 4);
	return UINT64_C(1) << (PAGE_BITS + level * PAGE_LEVEL_BITS);
}

/**
 * Get the start address of the range mapped by the next block of the given
 * level.
 */
static ptable_addr_t mm_start_of_next_block(ptable_addr_t addr,
					    mm_level_t level)
{
	assert(level <= 4);
	return align_up(addr + 1, mm_entry_size(level));
}

/**
 * For a given address, calculates the maximum (plus one) address that can be
 * represented by the same table at the given level.
 */
static ptable_addr_t mm_level_end(ptable_addr_t addr, mm_level_t level)
{
	size_t offset = PAGE_BITS + (level + 1) * PAGE_LEVEL_BITS;

	return ((addr >> offset) + 1) << offset;
}

/**
 * For a given address, calculates the index at which its entry is stored in a
 * table at the given level. See also Arm ARM, table D8-14
 * - `level == 4`: bits[51:48]
 * - `level == 3`: bits[47:39]
 * - `level == 2`: bits[38:30]
 * - `level == 1`: bits[29:21]
 * - `level == 0`: bits[20:12]
 */
static size_t mm_index(ptable_addr_t addr, mm_level_t level)
{
	ptable_addr_t v = addr >> (PAGE_BITS + level * PAGE_LEVEL_BITS);

	return v & ((UINT64_C(1) << PAGE_LEVEL_BITS) - 1);
}

/**
 * Allocates a new page table.
 */
static struct mm_page_table *mm_alloc_page_tables(size_t count,
						  struct mpool *ppool)
{
	if (count == 1) {
		return mpool_alloc(ppool);
	}

	return mpool_alloc_contiguous(ppool, count, count);
}

/**
 * Returns the root level in the page table given the flags.
 */
static mm_level_t mm_root_level(const struct mm_ptable *ptable)
{
	return ptable->stage1 ? arch_mm_stage1_root_level()
			      : arch_mm_stage2_root_level();
}

/**
 * Returns the number of root-level tables given the flags.
 */
static uint8_t mm_root_table_count(const struct mm_ptable *ptable)
{
	return ptable->stage1 ? arch_mm_stage1_root_table_count()
			      : arch_mm_stage2_root_table_count();
}

/**
 * Invalidates the TLB for the given address range.
 */
static void mm_invalidate_tlb(const struct mm_ptable *ptable,
			      ptable_addr_t begin, ptable_addr_t end,
			      bool non_secure)
{
	if (ptable->stage1) {
		arch_mm_invalidate_stage1_range(ptable->id, va_init(begin),
						va_init(end));
	} else {
		arch_mm_invalidate_stage2_range(ptable->id, ipa_init(begin),
						ipa_init(end), non_secure);
	}
}

/**
 * Frees all page-table-related memory associated with the given pte at the
 * given level, including any subtables recursively.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void mm_free_page_pte(pte_t pte, mm_level_t level, struct mpool *ppool)
{
	struct mm_page_table *table;

	if (!arch_mm_pte_is_table(pte, level)) {
		return;
	}

	/* Recursively free any subtables. */
	table = arch_mm_table_from_pte(pte, level);
	for (size_t i = 0; i < MM_PTE_PER_PAGE; ++i) {
		mm_free_page_pte(table->entries[i], level - 1, ppool);
	}

	/* Free the table itself. */
	mpool_free(ppool, table);
}

/**
 * Returns the first address which cannot be encoded in page tables given by
 * `flags`. It is the exclusive end of the address space created by the tables.
 */
ptable_addr_t mm_ptable_addr_space_end(const struct mm_ptable *ptable)
{
	return mm_root_table_count(ptable) *
	       mm_entry_size(mm_root_level(ptable));
}

/**
 * Initialises the given page table.
 */
bool mm_ptable_init(struct mm_ptable *ptable, mm_asid_t id, bool stage1,
		    struct mpool *ppool)
{
	struct mm_page_table *root_tables;
	uint8_t root_table_count = stage1 ? arch_mm_stage1_root_table_count()
					  : arch_mm_stage2_root_table_count();
	mm_level_t root_level = stage1 ? arch_mm_stage1_root_level()
				       : arch_mm_stage2_root_level();

	root_tables = mm_alloc_page_tables(root_table_count, ppool);
	if (root_tables == NULL) {
		return false;
	}

	for (size_t i = 0; i < root_table_count; i++) {
		for (size_t j = 0; j < MM_PTE_PER_PAGE; j++) {
			root_tables[i].entries[j] =
				arch_mm_absent_pte(root_level - 1);
		}
	}

	/*
	 * TODO: halloc could return a virtual or physical address if mm not
	 * enabled?
	 */
	ptable->id = id;
	ptable->root_tables = root_tables;
	ptable->stage1 = stage1;
	return true;
}

/**
 * Frees all memory associated with the give page table.
 */
void mm_ptable_fini(const struct mm_ptable *ptable, struct mpool *ppool)
{
	struct mm_page_table *root_tables = ptable->root_tables;
	mm_level_t root_level = mm_root_level(ptable);
	uint8_t root_table_count = mm_root_table_count(ptable);

	for (size_t i = 0; i < root_table_count; ++i) {
		for (size_t j = 0; j < MM_PTE_PER_PAGE; ++j) {
			mm_free_page_pte(root_tables[i].entries[j],
					 root_level - 1, ppool);
		}
	}

	mpool_add_chunk(ppool, root_tables,
			sizeof(struct mm_page_table) * root_table_count);
}

/**
 * Replaces a page table entry with the given value. If both old and new values
 * are valid, it performs a break-before-make sequence where it first writes an
 * invalid value to the PTE, flushes the TLB, then writes the actual new value.
 * This is to prevent cases where CPUs have different 'valid' values in their
 * TLBs, which may result in issues for example in cache coherency.
 */
static void mm_replace_entry(const struct mm_ptable *ptable,
			     ptable_addr_t begin, pte_t *pte, pte_t new_pte,
			     mm_level_t level, bool non_secure,
			     struct mpool *ppool)
{
	pte_t v = *pte;

	/*
	 * We need to do the break-before-make sequence if both values are
	 * present and the TLB is being invalidated.
	 */
	if ((ptable->stage1 || mm_stage2_invalidate) &&
	    arch_mm_pte_is_valid(v, level)) {
		*pte = arch_mm_absent_pte(level);
		mm_invalidate_tlb(ptable, begin, begin + mm_entry_size(level),
				  non_secure);
	}

	/* Assign the new pte. */
	*pte = new_pte;

	/* Free pages that aren't in use anymore. */
	mm_free_page_pte(v, level, ppool);
}

/**
 * Populates the provided page table entry with a reference to another table if
 * needed, that is, if it does not yet point to another table.
 *
 * Returns a pointer to the table the entry now points to.
 */
static struct mm_page_table *mm_populate_table_pte(struct mm_ptable *ptable,
						   ptable_addr_t begin,
						   pte_t *pte, mm_level_t level,
						   bool non_secure,
						   struct mpool *ppool)
{
	struct mm_page_table *ntable;
	pte_t v = *pte;
	pte_t new_pte;
	size_t inc;
	mm_level_t level_below = level - 1;

	/* Just return pointer to table if it's already populated. */
	if (arch_mm_pte_is_table(v, level)) {
		return arch_mm_table_from_pte(v, level);
	}

	/* Allocate a new table. */
	ntable = mm_alloc_page_tables(1, ppool);
	if (ntable == NULL) {
		dlog_error("Failed to allocate memory for page table\n");
		return NULL;
	}

	/* Determine template for new pte and its increment. */
	if (arch_mm_pte_is_block(v, level)) {
		inc = mm_entry_size(level_below);
		new_pte = arch_mm_block_pte(level_below,
					    arch_mm_block_from_pte(v, level),
					    arch_mm_pte_attrs(v, level));
	} else {
		inc = 0;
		new_pte = arch_mm_absent_pte(level_below);
	}

	/* Initialise entries in the new table. */
	for (size_t i = 0; i < MM_PTE_PER_PAGE; i++) {
		ntable->entries[i] = new_pte;
		new_pte += inc;
	}

	/* Ensure initialisation is visible before updating the pte. */
	atomic_thread_fence(memory_order_release);

	/* Replace the pte entry, doing a break-before-make if needed. */
	mm_replace_entry(ptable, begin, pte,
			 arch_mm_table_pte(level, pa_init((uintpaddr_t)ntable)),
			 level, non_secure, ppool);

	return ntable;
}

/**
 * Updates the page table at the given level to map the given address range to a
 * physical range using the provided (architecture-specific) attributes. Or if
 * `flags.unmap` is set, unmap the given range instead.
 *
 * This function calls itself recursively if it needs to update additional
 * levels, but the recursion is bound by the maximum number of levels in a page
 * table.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static bool mm_map_level(struct mm_ptable *ptable, ptable_addr_t begin,
			 ptable_addr_t end, mm_attr_t attrs,
			 struct mm_page_table *child_table, mm_level_t level,
			 struct mm_flags flags, struct mpool *ppool)
{
	pte_t *pte = &child_table->entries[mm_index(begin, level)];
	ptable_addr_t level_end = mm_level_end(begin, level);
	size_t entry_size = mm_entry_size(level);
	bool commit = flags.commit;
	bool unmap = flags.unmap;
	bool non_secure = ((attrs & (1ULL << 57)) != 0);

	/* Cap end so that we don't go over the current level max. */
	if (end > level_end) {
		end = level_end;
	}

	/* Fill each entry in the table. */
	while (begin < end) {
		if (unmap ? !arch_mm_pte_is_present(*pte, level)
			  : arch_mm_pte_is_block(*pte, level) &&
				    arch_mm_pte_attrs(*pte, level) == attrs) {
			/*
			 * If the entry is already mapped with the right
			 * attributes, or already absent in the case of
			 * unmapping, no need to do anything; carry on to the
			 * next entry.
			 */
		} else if ((end - begin) >= entry_size &&
			   (unmap || arch_mm_is_block_allowed(level)) &&
			   is_aligned(begin, entry_size)) {
			/*
			 * If the entire entry is within the region we want to
			 * map, map/unmap the whole entry.
			 */
			if (commit) {
				pte_t new_pte =
					unmap ? arch_mm_absent_pte(level)
					      : arch_mm_block_pte(
							level, pa_init(begin),
							attrs);
				mm_replace_entry(ptable, begin, pte, new_pte,
						 level, non_secure, ppool);
			}
		} else {
			/*
			 * If the entry is already a subtable get it; otherwise
			 * replace it with an equivalent subtable and get that.
			 */
			struct mm_page_table *nt = mm_populate_table_pte(
				ptable, begin, pte, level, non_secure, ppool);
			if (nt == NULL) {
				return false;
			}

			/*
			 * Recurse to map/unmap the appropriate entries within
			 * the subtable.
			 */
			if (!mm_map_level(ptable, begin, end, attrs, nt,
					  level - 1, flags, ppool)) {
				return false;
			}
		}

		begin = mm_start_of_next_block(begin, level);
		pte++;
	}

	return true;
}

/**
 * Updates the page table from the root to map the given address range to a
 * physical range using the provided (architecture-specific) attributes.
 *
 * Flags:
 * - `flags.unmap`: unmap the given range instead of mapping it.
 * - `flags.commit`: the change is only committed if this flag is set.
 */
static bool mm_ptable_identity_map(struct mm_ptable *ptable, paddr_t pa_begin,
				   paddr_t pa_end, mm_attr_t attrs,
				   struct mm_flags flags, struct mpool *ppool)
{
	mm_level_t root_level = mm_root_level(ptable);
	ptable_addr_t ptable_end = mm_ptable_addr_space_end(ptable);
	ptable_addr_t end = mm_round_up_to_page(pa_addr(pa_end));
	ptable_addr_t begin = mm_round_down_to_page(pa_addr(pa_begin));
	struct mm_page_table *root_table =
		&ptable->root_tables[mm_index(begin, root_level)];

	/*
	 * Assert condition to communicate the API constraint of
	 * mm_root_level(), that isn't encoded in the types, to the static
	 * analyzer.
	 */
	assert(root_level >= 3);

	/* Cap end to stay within the bounds of the page table. */
	if (end > ptable_end) {
		dlog_verbose(
			"ptable_map: input range end falls outside of ptable "
			"address space (%#016lx > %#016lx), capping to ptable "
			"address space end\n",
			end, ptable_end);
		end = ptable_end;
	}

	if (begin >= end) {
		dlog_verbose(
			"ptable_map: input range is backwards (%#016lx >= "
			"%#016lx), request will have no effect\n",
			begin, end);
	} else if (pa_addr(pa_begin) >= pa_addr(pa_end)) {
		dlog_verbose(
			"ptable_map: input range was backwards (%#016lx >= "
			"%#016lx), but due to rounding the range %#016lx to "
			"%#016lx will be mapped\n",
			begin, end, pa_addr(pa_begin), pa_addr(pa_end));
	}

	while (begin < end) {
		if (!mm_map_level(ptable, begin, end, attrs, root_table,
				  root_level - 1, flags, ppool)) {
			return false;
		}
		begin = mm_start_of_next_block(begin, root_level);
		root_table++;
	}

	/*
	 * All TLB invalidations must be complete already if any entries were
	 * replaced by mm_replace_entry. Sync all page table writes so that code
	 * following this can use them.
	 */
	arch_mm_sync_table_writes();

	return true;
}

/*
 * Prepares the given page table for the given address mapping such that it
 * will be able to commit the change without failure. It does so by ensuring
 * the smallest granularity needed is available. This remains valid provided
 * subsequent operations do not decrease the granularity.
 *
 * In particular, multiple calls to this function will result in the
 * corresponding calls to commit the changes to succeed.
 */
static bool mm_ptable_identity_prepare(struct mm_ptable *ptable,
				       paddr_t pa_begin, paddr_t pa_end,
				       mm_attr_t attrs, struct mm_flags flags,
				       struct mpool *ppool)
{
	flags.commit = false;
	return mm_ptable_identity_map(ptable, pa_begin, pa_end, attrs, flags,
				      ppool);
}

/**
 * Commits the given address mapping to the page table assuming the operation
 * cannot fail. `mm_ptable_identity_prepare` must used correctly before this to
 * ensure this condition.
 *
 * Without the table being properly prepared, the commit may only partially
 * complete if it runs out of memory resulting in an inconsistent state that
 * isn't handled.
 *
 * Since the non-failure assumtion is used in the reasoning about the atomicity
 * of higher level memory operations, any detected violations result in a panic.
 *
 * TODO: remove ppool argument to be sure no changes are made.
 */
static void mm_ptable_identity_commit(struct mm_ptable *ptable,
				      paddr_t pa_begin, paddr_t pa_end,
				      mm_attr_t attrs, struct mm_flags flags,
				      struct mpool *ppool)
{
	flags.commit = true;
	CHECK(mm_ptable_identity_map(ptable, pa_begin, pa_end, attrs, flags,
				     ppool));
}

/**
 * Updates the given table such that the given physical address range is mapped
 * or not mapped into the address space with the architecture-agnostic mode
 * provided.
 *
 * The page table is updated using the separate prepare and commit stages so
 * that, on failure, a partial update of the address space cannot happen. The
 * table may be left with extra internal tables but the address space is
 * unchanged.
 */
static bool mm_ptable_identity_update(struct mm_ptable *ptable,
				      paddr_t pa_begin, paddr_t pa_end,
				      mm_attr_t attrs, struct mm_flags flags,
				      struct mpool *ppool)
{
	if (!mm_ptable_identity_prepare(ptable, pa_begin, pa_end, attrs, flags,
					ppool)) {
		return false;
	}

	mm_ptable_identity_commit(ptable, pa_begin, pa_end, attrs, flags,
				  ppool);

	return true;
}

static void mm_dump_entries(const pte_t *entries, mm_level_t level,
			    uint32_t indent);

static void mm_dump_block_entry(pte_t entry, mm_level_t level, uint32_t indent)
{
	mm_attr_t attrs = arch_mm_pte_attrs(entry, level);
	paddr_t addr = arch_mm_block_from_pte(entry, level);

	if (arch_mm_pte_is_valid(entry, level)) {
		if (level == 0) {
			dlog("page {\n");
		} else {
			dlog("block {\n");
		}
	} else {
		dlog("invalid_block {\n");
	}

	indent += 1;
	{
		dlog_indent(indent, ".addr  = %#016lx\n", pa_addr(addr));
		dlog_indent(indent, ".attrs = %#016lx\n", attrs);
	}
	indent -= 1;
	dlog_indent(indent, "}");
}

// NOLINTNEXTLINE(misc-no-recursion)
static void mm_dump_table_entry(pte_t entry, mm_level_t level, uint32_t indent)
{
	dlog("table {\n");
	indent += 1;
	{
		mm_attr_t attrs = arch_mm_pte_attrs(entry, level);
		const struct mm_page_table *child_table =
			arch_mm_table_from_pte(entry, level);
		paddr_t addr = pa_init((uintpaddr_t)child_table);

		dlog_indent(indent, ".pte   = %#016lx,\n", entry);
		dlog_indent(indent, ".attrs = %#016lx,\n", attrs);
		dlog_indent(indent, ".addr  = %#016lx,\n", pa_addr(addr));
		dlog_indent(indent, ".entries = ");
		mm_dump_entries(child_table->entries, level - 1, indent);
		dlog(",\n");
	}
	indent -= 1;
	dlog_indent(indent, "}");
}

// NOLINTNEXTLINE(misc-no-recursion)
static void mm_dump_entry(pte_t entry, mm_level_t level, uint32_t indent)
{
	switch (arch_mm_pte_type(entry, level)) {
	case PTE_TYPE_ABSENT:
		dlog("absent {}");
		break;
	case PTE_TYPE_INVALID_BLOCK:
	case PTE_TYPE_VALID_BLOCK: {
		mm_dump_block_entry(entry, level, indent);
		break;
	}
	case PTE_TYPE_TABLE: {
		mm_dump_table_entry(entry, level, indent);
		break;
	}
	}
}

// NOLINTNEXTLINE(misc-no-recursion)
static void mm_dump_entries(const pte_t *entries, mm_level_t level,
			    uint32_t indent)
{
	dlog("{\n");
	indent += 1;

	for (size_t i = 0; i < MM_PTE_PER_PAGE; i++) {
		pte_t entry = entries[i];

		if (arch_mm_pte_is_absent(entry, level)) {
			continue;
		}

		dlog_indent(indent, "[level = %u, index = %zu] = ", level, i);
		mm_dump_entry(entry, level, indent);
		dlog(",\n");
	}

	indent -= 1;
	dlog_indent(indent, "}");
}

/**
 * Writes the given table to the debug log.
 */
static void mm_ptable_dump(const struct mm_ptable *ptable)
{
	struct mm_page_table *root_tables = ptable->root_tables;
	mm_level_t root_level = mm_root_level(ptable);
	uint8_t root_table_count = mm_root_table_count(ptable);
	uint32_t indent = 0;

	dlog_indent(indent, "mm_ptable {\n");
	indent += 1;
	{
		dlog_indent(indent, ".stage = %s,\n",
			    ptable->stage1 ? "stage1" : "stage2");
		dlog_indent(indent, ".id = %hu,\n", ptable->id);
		dlog_indent(indent, ".root_tables = {\n");

		indent += 1;
		{
			for (size_t i = 0; i < root_table_count; ++i) {
				dlog_indent(
					indent,
					"[level = %u, index = %zu].entries = ",
					root_level, i);
				mm_dump_entries(root_tables[i].entries,
						root_level - 1, indent);
				dlog(",\n");
			}
		}
		indent -= 1;
		dlog_indent(indent, "},\n");
	}
	indent -= 1;
	dlog_indent(indent, "}\n");
}

/**
 * Given the table PTE entries all have identical attributes, returns the single
 * entry with which it can be replaced.
 */
static pte_t mm_merge_table_pte(pte_t table_pte, mm_level_t level)
{
	struct mm_page_table *table;
	mm_attr_t block_attrs;
	mm_attr_t table_attrs;
	mm_attr_t combined_attrs;
	paddr_t block_address;

	table = arch_mm_table_from_pte(table_pte, level);

	if (!arch_mm_pte_is_present(table->entries[0], level - 1)) {
		return arch_mm_absent_pte(level);
	}

	/* Might not be possible to merge the table into a single block. */
	if (!arch_mm_is_block_allowed(level)) {
		return table_pte;
	}

	/* Replace table with a single block, with equivalent attributes. */
	block_attrs = arch_mm_pte_attrs(table->entries[0], level - 1);
	table_attrs = arch_mm_pte_attrs(table_pte, level);
	combined_attrs =
		arch_mm_combine_table_entry_attrs(table_attrs, block_attrs);
	block_address = arch_mm_block_from_pte(table->entries[0], level - 1);

	return arch_mm_block_pte(level, block_address, combined_attrs);
}

/**
 * Defragments the given PTE by recursively replacing any tables with blocks or
 * absent entries where possible.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void mm_ptable_defrag_entry(struct mm_ptable *ptable,
				   ptable_addr_t base_addr, pte_t *entry,
				   mm_level_t level, bool non_secure,
				   struct mpool *ppool)
{
	struct mm_page_table *child_table;
	bool mergeable;
	bool base_present;
	mm_attr_t base_attrs;
	pte_t new_entry;

	if (!arch_mm_pte_is_table(*entry, level)) {
		return;
	}

	child_table = arch_mm_table_from_pte(*entry, level);

	/* Defrag the first entry in the table and use it as the base entry. */
	static_assert(MM_PTE_PER_PAGE >= 1, "There must be at least one PTE.");

	mm_ptable_defrag_entry(ptable, base_addr, &(child_table->entries[0]),
			       level - 1, non_secure, ppool);

	base_present =
		arch_mm_pte_is_present(child_table->entries[0], level - 1);
	base_attrs = arch_mm_pte_attrs(child_table->entries[0], level - 1);

	/*
	 * Defrag the remaining entries in the table and check whether they are
	 * compatible with the base entry meaning the table can be merged into a
	 * block entry. It assumes addresses are contiguous due to identity
	 * mapping.
	 */
	mergeable = true;
	for (size_t i = 1; i < MM_PTE_PER_PAGE; ++i) {
		bool present;
		ptable_addr_t block_addr =
			base_addr + (i * mm_entry_size(level - 1));

		mm_ptable_defrag_entry(ptable, block_addr,
				       &(child_table->entries[i]), level - 1,
				       non_secure, ppool);

		present = arch_mm_pte_is_present(child_table->entries[i],
						 level - 1);

		if (present != base_present) {
			mergeable = false;
			continue;
		}

		if (!present) {
			continue;
		}

		if (!arch_mm_pte_is_block(child_table->entries[i], level - 1)) {
			mergeable = false;
			continue;
		}

		if (arch_mm_pte_attrs(child_table->entries[i], level - 1) !=
		    base_attrs) {
			mergeable = false;
			continue;
		}
	}

	if (!mergeable) {
		return;
	}

	new_entry = mm_merge_table_pte(*entry, level);
	if (*entry != new_entry) {
		mm_replace_entry(ptable, base_addr, entry, (uintptr_t)new_entry,
				 level, non_secure, ppool);
	}
}

/**
 * Defragments the given page table by converting page table references to
 * blocks whenever possible.
 */
static void mm_ptable_defrag(struct mm_ptable *ptable, bool non_secure,
			     struct mpool *ppool)
{
	struct mm_page_table *root_tables = ptable->root_tables;
	mm_level_t root_level = mm_root_level(ptable);
	uint8_t root_table_count = mm_root_table_count(ptable);
	ptable_addr_t block_addr = 0;

	/*
	 * Loop through each entry in the table. If it points to another table,
	 * check if that table can be replaced by a block or an absent entry.
	 */
	for (size_t i = 0; i < root_table_count; ++i) {
		for (size_t j = 0; j < MM_PTE_PER_PAGE; ++j) {
			mm_ptable_defrag_entry(
				ptable, block_addr, &root_tables[i].entries[j],
				root_level - 1, non_secure, ppool);
			block_addr = mm_start_of_next_block(block_addr,
							    root_level - 1);
		}
	}

	arch_mm_sync_table_writes();
}

struct mm_get_attrs_state {
	/**
	 * The attributes the range is mapped with.
	 * Only valid if `got_attrs` is true.
	 */
	mm_attr_t attrs;
	/**
	 * The address of the first page that does not match the attributes of
	 * the pages before it in the range.
	 * Only valid if `got_mismatch` is true.
	 */
	ptable_addr_t mismatch;
	bool got_attrs : 1;
	bool got_mismatch : 1;
};

/**
 * Gets the attributes applied to the given range of stage-2 addresses at the
 * given level.
 *
 * The `got_attrs` argument is initially passed as false until `attrs` contains
 * attributes of the memory region at which point it is passed as true.
 *
 * The value returned in `attrs` is only valid if the function returns true.
 *
 * Returns true if the whole range has the same attributes and false otherwise.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static struct mm_get_attrs_state mm_ptable_get_attrs_level(
	const struct mm_page_table *table, ptable_addr_t begin,
	ptable_addr_t end, mm_level_t level, struct mm_get_attrs_state state)
{
	const pte_t *pte = &table->entries[mm_index(begin, level)];
	ptable_addr_t level_end = mm_level_end(begin, level);

	/* Cap end so that we don't go over the current level max. */
	if (end > level_end) {
		end = level_end;
	}

	/* Check that each entry is owned. */
	while (begin < end && !state.got_mismatch) {
		switch (arch_mm_pte_type(*pte, level)) {
		case PTE_TYPE_TABLE: {
			const struct mm_page_table *child_table =
				arch_mm_table_from_pte(*pte, level);
			state = mm_ptable_get_attrs_level(
				child_table, begin, end, level - 1, state);
			break;
		}

		case PTE_TYPE_ABSENT:
		case PTE_TYPE_INVALID_BLOCK:
		case PTE_TYPE_VALID_BLOCK: {
			mm_attr_t block_attrs = arch_mm_pte_attrs(*pte, level);

			if (state.got_attrs && block_attrs != state.attrs) {
				state.mismatch = begin;
				state.got_mismatch = true;
				continue;
			}

			state.got_attrs = true;
			state.attrs = block_attrs;
			break;
		}
		}

		begin = mm_start_of_next_block(begin, level);
		pte++;
	}

	/* The entry is a valid block. */
	return state;
}

/**
 * Gets the attributes applied to the given range of addresses in the page
 * tables.
 *
 * The value returned in `attrs` is only valid if the function returns true.
 *
 * Returns true if the whole range has the same attributes and false otherwise.
 */
static struct mm_get_attrs_state mm_get_attrs(const struct mm_ptable *ptable,
					      ptable_addr_t begin,
					      ptable_addr_t end)
{
	mm_level_t root_level = mm_root_level(ptable);
	ptable_addr_t ptable_end = mm_ptable_addr_space_end(ptable);
	struct mm_page_table *root_table;
	struct mm_get_attrs_state state = {0};

	if (begin >= end) {
		dlog_verbose(
			"mm_get: input range is backwards (%#016lx >= "
			"%#016lx)\n",
			begin, end);
	}

	begin = mm_round_down_to_page(begin);
	end = mm_round_up_to_page(end);

	/* Fail if the addresses are out of range. */
	if (end > ptable_end) {
		return state;
	}

	root_table = &ptable->root_tables[mm_index(begin, root_level)];
	while (begin < end && !state.got_mismatch) {
		state = mm_ptable_get_attrs_level(root_table, begin, end,
						  root_level - 1, state);

		begin = mm_start_of_next_block(begin, root_level);
		root_table++;
	}

	return state;
}

bool mm_vm_init(struct mm_ptable *ptable, mm_asid_t id, struct mpool *ppool)
{
	return mm_ptable_init(ptable, id, false, ppool);
}

void mm_vm_fini(const struct mm_ptable *ptable, struct mpool *ppool)
{
	mm_ptable_fini(ptable, ppool);
}

/**
 * Selects flags to pass to the page table manipulation operation based on the
 * mapping mode.
 */
static struct mm_flags mm_mode_to_flags(mm_mode_t mode)
{
	struct mm_flags flags = {0};

	if ((mode & MM_MODE_UNMAPPED_MASK) == MM_MODE_UNMAPPED_MASK) {
		flags.unmap = true;
	}

	return flags;
}

/**
 * See `mm_ptable_identity_prepare`.
 *
 * This must be called before `mm_identity_commit` for the same mapping.
 *
 * Returns true on success, or false if the update would fail.
 */
bool mm_identity_prepare(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			 mm_mode_t mode, struct mpool *ppool)
{
	struct mm_flags flags = mm_mode_to_flags(mode);

	assert(ptable->stage1);
	return mm_ptable_identity_prepare(ptable, begin, end,
					  arch_mm_mode_to_stage1_attrs(mode),
					  flags, ppool);
}

/**
 * See `mm_ptable_identity_commit`.
 *
 * `mm_identity_prepare` must be called before this for the same mapping.
 */
void *mm_identity_commit(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			 mm_mode_t mode, struct mpool *ppool)
{
	struct mm_flags flags = mm_mode_to_flags(mode);

	assert(ptable->stage1);
	mm_ptable_identity_commit(ptable, begin, end,
				  arch_mm_mode_to_stage1_attrs(mode), flags,
				  ppool);
	return ptr_from_va(va_from_pa(begin));
}

/**
 * See `mm_ptable_identity_prepare`.
 *
 * This must be called before `mm_vm_identity_commit` for the same mapping.
 *
 * Returns true on success, or false if the update would fail.
 */
bool mm_vm_identity_prepare(struct mm_ptable *ptable, paddr_t begin,
			    paddr_t end, mm_mode_t mode, struct mpool *ppool)
{
	struct mm_flags flags = mm_mode_to_flags(mode);

	return mm_ptable_identity_prepare(ptable, begin, end,
					  arch_mm_mode_to_stage2_attrs(mode),
					  flags, ppool);
}

/**
 * See `mm_ptable_identity_commit`.
 *
 * `mm_vm_identity_prepare` must be called before this for the same mapping.
 */
void mm_vm_identity_commit(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			   mm_mode_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	struct mm_flags flags = mm_mode_to_flags(mode);

	mm_ptable_identity_commit(ptable, begin, end,
				  arch_mm_mode_to_stage2_attrs(mode), flags,
				  ppool);

	if (ipa != NULL) {
		*ipa = ipa_from_pa(begin);
	}
}

/**
 * Updates a VM's page table such that the given physical address range is
 * mapped in the address space at the corresponding address range in the
 * architecture-agnostic mode provided.
 *
 * mm_vm_defrag should always be called after a series of page table updates,
 * whether they succeed or fail. This is because on failure extra page table
 * entries may have been allocated and then not used, while on success it may be
 * possible to compact the page table by merging several entries into a block.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 */
bool mm_vm_identity_map(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			mm_mode_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	struct mm_flags flags = mm_mode_to_flags(mode);
	bool success = mm_ptable_identity_update(
		ptable, begin, end, arch_mm_mode_to_stage2_attrs(mode), flags,
		ppool);

	if (success && ipa != NULL) {
		*ipa = ipa_from_pa(begin);
	}

	return success;
}

/**
 * Updates the VM's table such that the given physical address range has no
 * connection to the VM.
 */
bool mm_vm_unmap(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
		 struct mpool *ppool)
{
	mm_mode_t mode = MM_MODE_UNMAPPED_MASK;

	return mm_vm_identity_map(ptable, begin, end, mode, ppool, NULL);
}

/**
 * Write the given page table of a VM to the debug log.
 */
void mm_vm_dump(const struct mm_ptable *ptable)
{
	mm_ptable_dump(ptable);
}

/**
 * Defragments a stage1 page table.
 */
void mm_stage1_defrag(struct mm_ptable *ptable, struct mpool *ppool)
{
	assert(ptable->stage1);
	mm_ptable_defrag(ptable, false, ppool);
}

/**
 * Defragments the VM page table.
 */
void mm_vm_defrag(struct mm_ptable *ptable, struct mpool *ppool,
		  bool non_secure)
{
	mm_ptable_defrag(ptable, non_secure, ppool);
}

/**
 * Gets the mode of the given range of intermediate physical addresses if they
 * are mapped with the same mode.
 *
 * Returns true if the range is mapped with the same mode and false otherwise.
 */
bool mm_vm_get_mode(const struct mm_ptable *ptable, ipaddr_t begin,
		    ipaddr_t end, mm_mode_t *mode)
{
	struct mm_get_attrs_state ret;
	bool success;

	ret = mm_get_attrs(ptable, ipa_addr(begin), ipa_addr(end));
	success = ret.got_attrs && !ret.got_mismatch;

	if (success && mode != NULL) {
		*mode = arch_mm_stage2_attrs_to_mode(ret.attrs);
	}

	return success;
}

bool mm_vm_get_mode_partial(const struct mm_ptable *ptable, ipaddr_t begin,
			    ipaddr_t end, mm_mode_t *mode, ipaddr_t *end_ret)
{
	struct mm_get_attrs_state ret;
	bool success;

	ret = mm_get_attrs(ptable, ipa_addr(begin), ipa_addr(end));
	success = ret.got_attrs;

	if (success && mode != NULL) {
		*mode = arch_mm_stage2_attrs_to_mode(ret.attrs);
	}

	if (success && end_ret != NULL) {
		*end_ret = ret.mismatch ? ipa_init(ret.mismatch) : end;
	}

	return success;
}

/**
 * Gets the mode of the given range of virtual addresses if they
 * are mapped with the same mode.
 *
 * Returns true if the range is mapped with the same mode and false otherwise.
 */
bool mm_get_mode(const struct mm_ptable *ptable, vaddr_t begin, vaddr_t end,
		 mm_mode_t *mode)
{
	struct mm_get_attrs_state ret;
	bool success;

	assert(ptable->stage1);

	ret = mm_get_attrs(ptable, va_addr(begin), va_addr(end));
	success = ret.got_attrs && !ret.got_mismatch;

	if (success && mode != NULL) {
		*mode = arch_mm_stage1_attrs_to_mode(ret.attrs);
	}

	return success;
}

bool mm_get_mode_partial(const struct mm_ptable *ptable, vaddr_t begin,
			 vaddr_t end, mm_mode_t *mode, vaddr_t *end_ret)
{
	struct mm_get_attrs_state ret;
	bool success;

	assert(ptable->stage1);

	ret = mm_get_attrs(ptable, va_addr(begin), va_addr(end));
	success = ret.got_attrs;

	if (success && mode != NULL) {
		*mode = arch_mm_stage1_attrs_to_mode(ret.attrs);
	}

	if (success && end_ret != NULL) {
		*end_ret = ret.mismatch ? va_init(ret.mismatch) : end;
	}

	return success;
}

struct mm_get_range_by_mode_state {
	/* Start address of range. */
	ptable_addr_t begin;
	/* End address of range. */
	ptable_addr_t end;
	/* Next starting address on subsequent calls. */
	ptable_addr_t next_start_addr;
	/* Mode collected from the range. */
	mm_mode_t ptable_mode;
	/* Mode was found in range. */
	bool mode_found : 1;
	/* Mismatch in mode was detected. */
	bool mismatch : 1;
};

/**
 * Recursively traverses page table looking for the mode provided,
 * if found, continues until either a mismatch occurs or
 * end-of-table is hit. Updates the passed in structure with the
 * range and mode information.
 */
// NOLINTNEXTLINE(misc-no-recursion)
void mm_get_range_by_mode_level(const struct mm_page_table *table,
				mm_level_t level, mm_mode_t mode, bool stage1,
				ptable_addr_t start_addr,
				struct mm_get_range_by_mode_state *state)
{
	ptable_addr_t current_addr = start_addr;
	const pte_t *pte = &table->entries[mm_index(current_addr, level)];
	ptable_addr_t level_end = mm_level_end(current_addr, level);

	/* Loop until the end of the table or a mismatch occurs. */
	while ((current_addr < level_end) && !state->mismatch) {
		/* If the table is invalid, continue. */
		if (!arch_mm_pte_is_present(*pte, level)) {
			/* If we had found a mode previously, mismatch. */
			if (state->mode_found) {
				state->mismatch = true;
				state->next_start_addr = current_addr;
				return;
			}
		} else if (arch_mm_pte_is_table(*pte, level - 1)) {
			const struct mm_page_table *child_table =
				arch_mm_table_from_pte(*pte, level);
			mm_get_range_by_mode_level(child_table, level - 1, mode,
						   stage1, current_addr, state);
		} else {
			/* Obtain the page-table entry attributes. */
			mm_attr_t block_attrs = arch_mm_pte_attrs(*pte, level);
			mm_mode_t curr_mode;

			/* From the attributes, obtain the mode. */
			if (stage1) {
				curr_mode = arch_mm_stage1_attrs_to_mode(
					block_attrs);
			} else {
				curr_mode = arch_mm_stage2_attrs_to_mode(
					block_attrs);
			}

			/* Check if the mode matches. */
			if ((!state->mode_found && (curr_mode & mode) != 0) ||
			    (state->mode_found &&
			     (state->ptable_mode == curr_mode))) {
				paddr_t ptable_addr =
					arch_mm_block_from_pte(*pte, level - 1);
				dlog_verbose("Mode Found at PTE Addr: %lx\n",
					     pa_addr(ptable_addr));

				/*
				 * If this is the first time finding the mode
				 * initialize the state variables.
				 */
				if (!state->mode_found) {
					state->begin = pa_addr(ptable_addr);
					state->ptable_mode = curr_mode;
					state->mode_found = true;
				}

				/* Update the end address. */
				state->end = pa_addr(ptable_addr);
			} else if (state->mode_found) {
				state->mismatch = true;
				state->next_start_addr = current_addr;
				return;
			}
		}

		current_addr = mm_start_of_next_block(current_addr, level);
		pte++;
	}
}

/**
 * Stage2 version of the mm_get_range_by_mode function, initializes state
 * before calling the recursive traversal function. Successful call finds
 * the mode provided within a given range.
 */
bool mm_vm_get_range_by_mode(const struct mm_ptable *ptable, ipaddr_t *begin,
			     ipaddr_t *end, mm_mode_t mode,
			     ipaddr_t *start_addr, mm_mode_t *ptable_mode)
{
	mm_level_t root_level;
	ptable_addr_t ptable_end;
	ptable_addr_t current_addr;
	struct mm_page_table *root_table;
	struct mm_get_range_by_mode_state state = {0};

	current_addr = ipa_addr(*start_addr);
	root_level = mm_root_level(ptable);
	ptable_end = mm_ptable_addr_space_end(ptable);
	root_table = &ptable->root_tables[mm_index(ipa_addr(*start_addr),
						   root_level)];

	assert(!ptable->stage1);

	while ((current_addr < ptable_end) && !state.mismatch) {
		mm_get_range_by_mode_level(root_table, root_level, mode,
					   ptable->stage1, current_addr,
					   &state);

		current_addr = mm_start_of_next_block(current_addr, root_level);
		root_table++;
	}

	if (state.mode_found) {
		*begin = ipa_init(state.begin);
		*end = ipa_init(state.end);
		*start_addr = ipa_init(state.next_start_addr);
		*ptable_mode = state.ptable_mode;
	}

	return state.mode_found;
}

/**
 * Stage1 version of the mm_get_range_by_mode function, initializes state
 * before calling the recursive traversal function. Successful call finds
 * the mode provided within a given range.
 */
bool mm_get_range_by_mode(const struct mm_ptable *ptable, vaddr_t *begin,
			  vaddr_t *end, mm_mode_t mode, vaddr_t *start_addr,
			  mm_mode_t *ptable_mode)
{
	mm_level_t root_level;
	ptable_addr_t ptable_end;
	ptable_addr_t current_addr;
	struct mm_page_table *root_table;
	struct mm_get_range_by_mode_state state = {0};

	assert(ptable->stage1);

	current_addr = va_addr(*start_addr);
	root_level = mm_root_level(ptable);
	ptable_end = mm_ptable_addr_space_end(ptable);
	root_table = &ptable->root_tables[mm_index(va_addr(*start_addr),
						   root_level)];

	while ((current_addr < ptable_end) && !state.mismatch) {
		mm_get_range_by_mode_level(root_table, root_level, mode,
					   ptable->stage1, current_addr,
					   &state);

		current_addr = mm_start_of_next_block(current_addr, root_level);
		root_table++;
	}

	if (state.mode_found) {
		*begin = va_init(state.begin);
		*end = va_init(state.end);
		*start_addr = va_init(state.next_start_addr);
		*ptable_mode = state.ptable_mode;
	}

	return state.mode_found;
}

static struct mm_stage1_locked mm_stage1_lock_unsafe(void)
{
	return (struct mm_stage1_locked){.ptable = &ptable};
}

struct mm_stage1_locked mm_lock_ptable_unsafe(struct mm_ptable *ptable)
{
	return (struct mm_stage1_locked){.ptable = ptable};
}

struct mm_stage1_locked mm_lock_stage1(void)
{
	sl_lock(&ptable_lock);
	return mm_stage1_lock_unsafe();
}

void mm_unlock_stage1(struct mm_stage1_locked *lock)
{
	CHECK(lock->ptable == &ptable);
	sl_unlock(&ptable_lock);
	lock->ptable = NULL;
}

/**
 * Updates the hypervisor page table such that the given physical address range
 * is mapped into the address space at the corresponding address range in the
 * architecture-agnostic mode provided.
 */
void *mm_identity_map(struct mm_stage1_locked stage1_locked, paddr_t begin,
		      paddr_t end, mm_mode_t mode, struct mpool *ppool)
{
	struct mm_flags flags = mm_mode_to_flags(mode);

	assert(stage1_locked.ptable->stage1);
	if (mm_ptable_identity_update(stage1_locked.ptable, begin, end,
				      arch_mm_mode_to_stage1_attrs(mode), flags,
				      ppool)) {
		return ptr_from_va(va_from_pa(begin));
	}

	return NULL;
}

/**
 * Updates the hypervisor table such that the given physical address range is
 * not mapped in the address space.
 */
bool mm_unmap(struct mm_stage1_locked stage1_locked, paddr_t begin, paddr_t end,
	      struct mpool *ppool)
{
	mm_mode_t mode = MM_MODE_UNMAPPED_MASK;

	return mm_identity_map(stage1_locked, begin, end, mode, ppool);
}

/**
 * Defragments the hypervisor page table.
 */
void mm_defrag(struct mm_stage1_locked stage1_locked, struct mpool *ppool)
{
	assert(stage1_locked.ptable->stage1);
	mm_ptable_defrag(stage1_locked.ptable, false, ppool);
}

/**
 * Initialises memory management for the hypervisor itself.
 */
bool mm_init(void)
{
	/* Locking is not enabled yet so fake it, */
	struct mm_stage1_locked stage1_locked = mm_stage1_lock_unsafe();
	ppool = memory_alloc_get_ppool();

	assert(ppool != NULL);

	dlog_info("text: %#lx - %#lx\n", pa_addr(layout_text_begin()),
		  pa_addr(layout_text_end()));
	dlog_info("rodata: %#lx - %#lx\n", pa_addr(layout_rodata_begin()),
		  pa_addr(layout_rodata_end()));
	dlog_info("data: %#lx - %#lx\n", pa_addr(layout_data_begin()),
		  pa_addr(layout_data_end()));
	dlog_info("stacks: %#lx - %#lx\n", pa_addr(layout_stacks_begin()),
		  pa_addr(layout_stacks_end()));

	/* ASID 0 is reserved for use by the hypervisor. */
	if (!mm_ptable_init(&ptable, 0, true, ppool)) {
		dlog_error("Unable to allocate memory for page table.\n");
		return false;
	}

	/* Initialize arch_mm before calling below mapping routines */
	if (!arch_mm_init(&ptable)) {
		return false;
	}

	/* Let console driver map pages for itself. */
	plat_console_mm_init(stage1_locked, ppool);

	/* Map each section. */
	CHECK(mm_identity_map(stage1_locked, layout_text_begin(),
			      layout_text_end(), MM_MODE_X, ppool) != NULL);

	CHECK(mm_identity_map(stage1_locked, layout_rodata_begin(),
			      layout_rodata_end(), MM_MODE_R, ppool) != NULL);

	CHECK(mm_identity_map(stage1_locked, layout_data_begin(),
			      layout_data_end(), MM_MODE_R | MM_MODE_W,
			      ppool) != NULL);

	/* Arch-specific stack mapping. */
	CHECK(arch_stack_mm_init(stage1_locked, ppool));

	return true;
}
