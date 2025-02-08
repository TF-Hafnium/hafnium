/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "hf/addr.h"
#include "hf/mm.h"

#include "vmapi/hf/ffa.h"

/**
 * Creates an absent PTE.
 */
pte_t arch_mm_absent_pte(mm_level_t level);

/**
 * Creates a table PTE.
 */
pte_t arch_mm_table_pte(mm_level_t level, paddr_t pa);

/**
 * Creates a block PTE.
 */
pte_t arch_mm_block_pte(mm_level_t level, paddr_t pa, mm_attr_t attrs);

enum mm_pte_type arch_mm_pte_type(pte_t pte, mm_level_t level);

/**
 * Checks whether a block is allowed at the given level of the page table.
 */
bool arch_mm_is_block_allowed(mm_level_t level);

static inline bool arch_mm_pte_is_absent(pte_t pte, mm_level_t level)
{
	return arch_mm_pte_type(pte, level) == PTE_TYPE_ABSENT;
}

/**
 * Determines if a PTE is present i.e. it contains information and therefore
 * needs to exist in the page table. Any non-absent PTE is present.
 */
static inline bool arch_mm_pte_is_present(pte_t pte, mm_level_t level)
{
	return !arch_mm_pte_is_absent(pte, level);
}

/**
 * Determines if a PTE is valid i.e. it can affect the address space. Tables and
 * valid blocks fall into this category. Invalid blocks do not as they hold
 * information about blocks that are not in the address space.
 */
static inline bool arch_mm_pte_is_valid(pte_t pte, mm_level_t level)
{
	switch (arch_mm_pte_type(pte, level)) {
	case PTE_TYPE_ABSENT:
	case PTE_TYPE_INVALID_BLOCK:
		return false;
	case PTE_TYPE_VALID_BLOCK:
	case PTE_TYPE_TABLE:
		return true;
	}
}

/**
 * Determines if a PTE is a block and represents an address range, valid or
 * invalid.
 */
static inline bool arch_mm_pte_is_block(pte_t pte, mm_level_t level)
{
	switch (arch_mm_pte_type(pte, level)) {
	case PTE_TYPE_ABSENT:
	case PTE_TYPE_TABLE:
		return false;
	case PTE_TYPE_INVALID_BLOCK:
	case PTE_TYPE_VALID_BLOCK:
		return true;
	}
}

/**
 * Determines if a PTE represents a reference to a table of PTEs.
 */
static inline bool arch_mm_pte_is_table(pte_t pte, mm_level_t level)
{
	return arch_mm_pte_type(pte, level) == PTE_TYPE_TABLE;
}

/**
 * Extracts the start address of the PTE range.
 */
paddr_t arch_mm_block_from_pte(pte_t pte, mm_level_t level);

/**
 * Extracts the address of the table referenced by the PTE.
 */
paddr_t arch_mm_table_from_pte(pte_t pte, mm_level_t level);

/**
 * Extracts the attributes of the PTE.
 */
mm_attr_t arch_mm_pte_attrs(pte_t pte, mm_level_t level);

/**
 * Merges the attributes of a block into those of its parent table.
 */
mm_attr_t arch_mm_combine_table_entry_attrs(mm_attr_t table_attrs,
					    mm_attr_t block_attrs);

/**
 * Invalidates the given range of stage-1 TLB.
 */
void arch_mm_invalidate_stage1_range(ffa_id_t asid, vaddr_t va_begin,
				     vaddr_t va_end);

/**
 * Invalidates the given range of stage-2 TLB.
 */
void arch_mm_invalidate_stage2_range(ffa_id_t vmid, ipaddr_t va_begin,
				     ipaddr_t va_end, bool non_secure);

/**
 * Writes back the given range of virtual memory to such a point that all cores
 * and devices will see the updated values. The corresponding cache lines are
 * also invalidated.
 */
void arch_mm_flush_dcache(void *base, size_t size);

/**
 * Sets the maximum level allowed in the page table for stage-1.
 */
void arch_mm_stage1_root_level_set(uint32_t pa_bits);

/**
 * Gets the maximum level allowed in the page table for stage-1.
 */
mm_level_t arch_mm_stage1_root_level(void);

/**
 * Gets the maximum level allowed in the page table for stage-2.
 */
mm_level_t arch_mm_stage2_root_level(void);

/**
 * Gets the number of concatenated page tables used at the root for stage-1.
 *
 * Tables are concatenated at the root to avoid introducing another level in the
 * page table meaning the table is shallow and wide. Each level is an extra
 * memory access when walking the table so keeping it shallow reduces the memory
 * accesses to aid performance.
 */
uint8_t arch_mm_stage1_root_table_count(void);

/**
 * Gets the number of concatenated page tables used at the root for stage-2.
 */
uint8_t arch_mm_stage2_root_table_count(void);

/**
 * Converts the mode into stage-1 attributes for a block PTE.
 */
mm_attr_t arch_mm_mode_to_stage1_attrs(mm_mode_t mode);

/**
 * Converts the mode into stage-2 attributes for a block PTE.
 */
mm_attr_t arch_mm_mode_to_stage2_attrs(mm_mode_t mode);

/**
 * Converts the stage-2 block attributes back to the corresponding mode.
 */
mm_mode_t arch_mm_stage2_attrs_to_mode(mm_attr_t attrs);

/**
 * Converts the stage-1 block attributes back to the corresponding mode.
 */
mm_mode_t arch_mm_stage1_attrs_to_mode(mm_attr_t attrs);

/**
 * Initializes the arch specific memory management.
 */
bool arch_mm_init(paddr_t table);

/**
 * Return the arch specific mm mode for send/recv pages of given VM ID.
 */
mm_mode_t arch_mm_extra_mode_from_vm(ffa_id_t id);

/**
 * Execute any barriers or synchronization that is required
 * by a given architecture, after page table writes.
 */
void arch_mm_sync_table_writes(void);

/**
 * Returns the maximum supported PA Range index.
 */
uint64_t arch_mm_get_pa_range(void);

/**
 * Returns the maximum supported PA Range in bits.
 */
uint32_t arch_mm_get_pa_bits(uint64_t pa_range);

/**
 * Returns VTCR_EL2 configured in arch_mm_init.
 */
uintptr_t arch_mm_get_vtcr_el2(void);

/**
 * Returns VSTCR_EL2 configured in arch_mm_init.
 */
uintptr_t arch_mm_get_vstcr_el2(void);
