/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hf/addr.h"
#include "hf/mpool.h"
#include "hf/static_assert.h"

typedef uint32_t mm_mode_t;
typedef uint64_t mm_attr_t;

/**
 * The level of a page table entry (i.e. how deep into the recursive tree
 * structure it is). See also Arm ARM, table D8-14.
 *
 * - `level == 4`: table entries (root)
 * - `level == 3`: table or block entries
 * - `level == 2`: table or block entries
 * - `level == 1`: table or block entries
 * - `level == 0`: page entries
 *
 * NOTE: The Arm ARM uses levels in the opposite order to our code: in the Arm
 * ARM, levels start at 0 (or -1 if 52 bits of PA are used, but that is not
 * supported by Hafnium) and page entries are at level 3. We go in the opposite
 * direction: levels start at 3 or 4 and page entries are at level 0. This is
 * because it makes the arithmetic and bit manipulation easier.
 */
typedef uint8_t mm_level_t;
typedef uint16_t mm_asid_t;

/*
 * A page table entry (PTE) will take one of the following forms:
 *
 *  1. absent        : There is no mapping.
 *  2. invalid block : Represents a block that is not in the address space.
 *  3. valid block   : Represents a block that is in the address space.
 *  4. table         : Represents a reference to a table of PTEs.
 * See Arm ARM, D8.3 (Translation table descriptor formats).
 */
enum mm_pte_type {
	PTE_TYPE_ABSENT,
	PTE_TYPE_INVALID_BLOCK,
	PTE_TYPE_VALID_BLOCK,
	PTE_TYPE_TABLE,
};

/* Keep macro alignment */
/* clang-format off */

#define PAGE_SIZE ((size_t)(1 << PAGE_BITS))
#define MM_PTE_PER_PAGE (PAGE_SIZE / sizeof(pte_t))

/* The following are arch-independent page mapping modes. */
#define MM_MODE_R (1U << 0) /* read */
#define MM_MODE_W (1U << 1) /* write */
#define MM_MODE_X (1U << 2) /* execute */
#define MM_MODE_D (1U << 3) /* device */

/*
 * Memory in stage-1 is either valid (present) or invalid (absent).
 *
 * Memory in stage-2 has more states to track sharing, borrowing and giving of
 * memory. The states are made up of three parts:
 *
 *  1. V = valid/invalid    : Whether the memory is part of the VM's address
 *                            space. A fault will be generated if accessed when
 *                            invalid.
 *  2. O = owned/unowned    : Whether the memory is owned by the VM.
 *  3. X = exclusive/shared : Whether access is exclusive to the VM or shared
 *                            with at most one other.
 *
 * These parts compose to form the following state:
 *
 *  -  V  O  X : Owner of memory with exclusive access.
 *  -  V  O !X : Owner of memory with access shared with at most one other VM.
 *  -  V !O  X : Borrower of memory with exclusive access.
 *  -  V !O !X : Borrower of memory where access is shared with the owner.
 *  - !V  O  X : Owner of memory lent to a VM that has exclusive access.
 *
 *  - !V  O !X : Unused. Owner of shared memory always has access.
 *  - !V !O  X : Unused. Next entry is used for invalid memory.
 *
 *  - !V !O !X : Invalid memory. Memory is unrelated to the VM.
 *
 *  Modes are selected so that owner of exclusive memory is the default.
 */
#define MM_MODE_INVALID (1U << 4)
#define MM_MODE_UNOWNED (1U << 5)
#define MM_MODE_SHARED  (1U << 6)

/* Map page as non-global. */
#define MM_MODE_NG (1U << 8)

/* Specifies if a mapping will be a user mapping(EL0). */
#define MM_MODE_USER    (1U << 9)

/* The mask for a mode that is considered unmapped. */
#define MM_MODE_UNMAPPED_MASK (MM_MODE_INVALID | MM_MODE_UNOWNED)

/* clang-format on */

/**
 * Flags for page table operations.
 * - commit: Commit the given range rather than preparing it.
 * - unmap: Unmap the given range rather than mapping it.
 */
struct mm_flags {
	bool commit : 1;
	bool unmap : 1;
};

#define MM_PPOOL_ENTRY_SIZE sizeof(struct mm_page_table)

struct mm_page_table {
	alignas(PAGE_SIZE) pte_t entries[MM_PTE_PER_PAGE];
};
static_assert(sizeof(struct mm_page_table) == PAGE_SIZE,
	      "A page table must take exactly one page.");
static_assert(alignof(struct mm_page_table) == PAGE_SIZE,
	      "A page table must be page aligned.");

struct mm_ptable {
	/**
	 * VMID/ASID associated with a page table. ASID 0 is reserved for use by
	 * the hypervisor.
	 */
	mm_asid_t id;
	/**
	 * Address of the root tables.
	 * At stage 1, concatenated tables are not used, so there is only one
	 * root table.
	 * At stage 2, concatenated tables are used, so there are multiple root
	 * tables (given by `arch_mm_root_table_count()`). The Arm ARM says
	 * there can be up to 16 root tables, but we only use 4.
	 */
	struct mm_page_table *root_tables;
	/** If true, the PT is a stage1 PT, otherwise it is a stage2 PT. */
	bool stage1 : 1;
};

/** The type of addresses stored in the page table. */
typedef uintvaddr_t ptable_addr_t;

/** Represents the currently locked stage-1 page table of the hypervisor. */
struct mm_stage1_locked {
	struct mm_ptable *ptable;
};

void mm_vm_enable_invalidation(void);

bool mm_ptable_init(struct mm_ptable *ptable, mm_asid_t id, bool stage1,
		    struct mpool *ppool);
ptable_addr_t mm_ptable_addr_space_end(const struct mm_ptable *ptable);

bool mm_vm_init(struct mm_ptable *ptable, mm_asid_t id, struct mpool *ppool);
void mm_vm_fini(const struct mm_ptable *ptable, struct mpool *ppool);

bool mm_identity_prepare(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			 mm_mode_t mode, struct mpool *ppool);
void *mm_identity_commit(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			 mm_mode_t mode, struct mpool *ppool);

bool mm_vm_identity_map(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			mm_mode_t mode, struct mpool *ppool, ipaddr_t *ipa);
bool mm_vm_identity_prepare(struct mm_ptable *ptable, paddr_t begin,
			    paddr_t end, mm_mode_t mode, struct mpool *ppool);
void mm_vm_identity_commit(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
			   mm_mode_t mode, struct mpool *ppool, ipaddr_t *ipa);
bool mm_vm_unmap(struct mm_ptable *ptable, paddr_t begin, paddr_t end,
		 struct mpool *ppool);
void mm_stage1_defrag(struct mm_ptable *ptable, struct mpool *ppool);
void mm_vm_defrag(struct mm_ptable *ptable, struct mpool *ppool,
		  bool non_secure);
void mm_vm_dump(const struct mm_ptable *ptable);
bool mm_vm_get_mode(const struct mm_ptable *ptable, ipaddr_t begin,
		    ipaddr_t end, mm_mode_t *mode);
bool mm_get_mode(const struct mm_ptable *ptable, vaddr_t begin, vaddr_t end,
		 mm_mode_t *mode);

struct mm_stage1_locked mm_lock_ptable_unsafe(struct mm_ptable *ptable);
struct mm_stage1_locked mm_lock_stage1(void);
void mm_unlock_stage1(struct mm_stage1_locked *lock);
void *mm_identity_map(struct mm_stage1_locked stage1_locked, paddr_t begin,
		      paddr_t end, mm_mode_t mode, struct mpool *ppool);
bool mm_unmap(struct mm_stage1_locked stage1_locked, paddr_t begin, paddr_t end,
	      struct mpool *ppool);
void mm_defrag(struct mm_stage1_locked stage1_locked, struct mpool *ppool);

bool mm_init(struct mpool *ppool);
