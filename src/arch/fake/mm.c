/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/mm.h"

#include "hf/mm.h"

/*
 * The fake architecture uses the mode flags to represent the attributes applied
 * to memory. The flags are shifted to avoid equality of modes and attributes.
 */
#define PTE_ATTR_MODE_SHIFT 48
#define PTE_ATTR_MODE_MASK                                               \
	((mm_attr_t)(MM_MODE_R | MM_MODE_W | MM_MODE_X | MM_MODE_D |     \
		     MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED) \
	 << PTE_ATTR_MODE_SHIFT)

/* The bit to distinguish a table from a block is the highest of the page bits.
 */
#define PTE_TABLE (UINT64_C(1) << (PAGE_BITS - 1))

/* Mask for the address part of an entry. */
#define PTE_ADDR_MASK (~(PTE_ATTR_MODE_MASK | (UINT64_C(1) << PAGE_BITS) - 1))

/* Offset the bits of each level so they can't be misued. */
#define PTE_LEVEL_SHIFT(lvl) ((lvl) * 2)

pte_t arch_mm_absent_pte(mm_level_t level)
{
	return ((mm_attr_t)(MM_MODE_INVALID | MM_MODE_UNOWNED | MM_MODE_SHARED)
		<< PTE_ATTR_MODE_SHIFT) >>
	       PTE_LEVEL_SHIFT(level);
}

pte_t arch_mm_table_pte(mm_level_t level, paddr_t pa)
{
	return (pa_addr(pa) | PTE_TABLE) >> PTE_LEVEL_SHIFT(level);
}

pte_t arch_mm_block_pte(mm_level_t level, paddr_t pa, mm_attr_t attrs)
{
	return (pa_addr(pa) | attrs) >> PTE_LEVEL_SHIFT(level);
}

bool arch_mm_is_block_allowed(mm_level_t level)
{
	(void)level;
	return true;
}

enum mm_pte_type arch_mm_pte_type(pte_t pte, mm_level_t level)
{
	bool invalid =
		(((pte << PTE_LEVEL_SHIFT(level)) >> PTE_ATTR_MODE_SHIFT) &
		 MM_MODE_INVALID) != 0;
	bool unowned =
		(((pte << PTE_LEVEL_SHIFT(level)) >> PTE_ATTR_MODE_SHIFT) &
		 MM_MODE_UNOWNED) != 0;
	bool table = ((pte << PTE_LEVEL_SHIFT(level)) & PTE_TABLE) != 0;

	if (invalid) {
		if (unowned) {
			return PTE_TYPE_ABSENT;
		}
		return PTE_TYPE_INVALID_BLOCK;
	}

	if (table) {
		return PTE_TYPE_TABLE;
	}

	return PTE_TYPE_VALID_BLOCK;
}

static paddr_t pte_addr(pte_t pte, mm_level_t level)
{
	return pa_init((pte << PTE_LEVEL_SHIFT(level)) & PTE_ADDR_MASK);
}

paddr_t arch_mm_block_from_pte(pte_t pte, mm_level_t level)
{
	assert(arch_mm_pte_is_block(pte, level));
	return pte_addr(pte, level);
}

struct mm_page_table *arch_mm_table_from_pte(pte_t pte, mm_level_t level)
{
	assert(arch_mm_pte_is_table(pte, level));
	return ptr_from_pa(pte_addr(pte, level));
}

mm_attr_t arch_mm_pte_attrs(pte_t pte, mm_level_t level)
{
	return (pte << PTE_LEVEL_SHIFT(level)) & PTE_ATTR_MODE_MASK;
}

mm_attr_t arch_mm_combine_table_entry_attrs(mm_attr_t table_attrs,
					    mm_attr_t block_attrs)
{
	return table_attrs | block_attrs;
}

void arch_mm_invalidate_stage1_range(ffa_id_t asid, vaddr_t va_begin,
				     vaddr_t va_end)
{
	(void)asid;
	(void)va_begin;
	(void)va_end;
	/* There's no modelling of the stage-1 TLB. */
}

void arch_mm_invalidate_stage2_range(ffa_id_t vmid, ipaddr_t va_begin,
				     ipaddr_t va_end, bool non_secure)
{
	(void)vmid;
	(void)va_begin;
	(void)va_end;
	(void)non_secure;
	/* There's no modelling of the stage-2 TLB. */
}

void arch_mm_flush_dcache(void *base, size_t size)
{
	(void)base;
	(void)size;
	/* There's no modelling of the cache. */
}

void arch_mm_stage1_root_level_set(uint32_t pa_bits)
{
	/* Not required to set this value as it's hardcoded to 3 */
	(void)pa_bits;
}

mm_level_t arch_mm_stage1_root_level(void)
{
	return 3;
}

mm_level_t arch_mm_stage2_root_level(void)
{
	return 3;
}

uint8_t arch_mm_stage1_root_table_count(void)
{
	return 1;
}

uint8_t arch_mm_stage2_root_table_count(void)
{
	/* Stage-2 has many concatenated page tables. */
	return 4;
}

mm_attr_t arch_mm_mode_to_stage1_attrs(mm_mode_t mode)
{
	return ((mm_attr_t)mode << PTE_ATTR_MODE_SHIFT) & PTE_ATTR_MODE_MASK;
}

mm_attr_t arch_mm_mode_to_stage2_attrs(mm_mode_t mode)
{
	return ((mm_attr_t)mode << PTE_ATTR_MODE_SHIFT) & PTE_ATTR_MODE_MASK;
}

mm_mode_t arch_mm_stage2_attrs_to_mode(mm_attr_t attrs)
{
	return attrs >> PTE_ATTR_MODE_SHIFT;
}

mm_mode_t arch_mm_stage1_attrs_to_mode(mm_attr_t attrs)
{
	return attrs >> PTE_ATTR_MODE_SHIFT;
}

bool arch_stack_mm_init(struct mm_stage1_locked stage1_locked,
			struct mpool *ppool)
{
	(void)stage1_locked;
	(void)ppool;
	return true;
}

bool arch_mm_init(const struct mm_ptable *ptable)
{
	/* No initialization required. */
	(void)ptable;
	return true;
}

mm_mode_t arch_mm_extra_mode_from_vm(ffa_id_t id)
{
	(void)id;

	return 0;
}

void arch_mm_sync_table_writes(void)
{
}

/**
 * Returns the maximum supported PA Range index.
 */
uint64_t arch_mm_get_pa_range(void)
{
	return 2;
}

/**
 * Returns the maximum supported PA Range in bits.
 */
uint32_t arch_mm_get_pa_bits(uint64_t pa_range)
{
	(void)pa_range;

	return 40;
}
