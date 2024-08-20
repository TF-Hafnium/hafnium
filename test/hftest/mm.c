/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/mm.h"

#include "test/hftest.h"

/* Number of pages reserved for page tables. Increase if necessary. */
#define PTABLE_PAGES 10

/**
 * Start address space mapping at 0x1000 for the mm to create a L2 table to
 * which the first L1 descriptor points to.
 * Provided SPMC and SP images reside below 1GB, same as peripherals, this
 * prevents a case in which the mm library has to break down the first
 * L1 block descriptor, while currently executing from a region within
 * the same L1 descriptor. This is not architecturally possible.
 */
#define HFTEST_STAGE1_START_ADDRESS (0x1000)

alignas(alignof(struct mm_page_table)) static char ptable_buf
	[sizeof(struct mm_page_table) * PTABLE_PAGES];

static struct mpool ppool;
static struct mm_ptable ptable;

struct mm_stage1_locked hftest_mm_get_stage1(void)
{
	return (struct mm_stage1_locked){.ptable = &ptable};
}

struct mpool *hftest_mm_get_ppool(void)
{
	return &ppool;
}

bool hftest_mm_init(void)
{
	struct mm_stage1_locked stage1_locked;

	/* Call arch init before calling below mapping routines */
	if (!arch_vm_mm_init()) {
		return false;
	}

	mpool_init(&ppool, sizeof(struct mm_page_table));
	if (!mpool_add_chunk(&ppool, ptable_buf, sizeof(ptable_buf))) {
		HFTEST_FAIL(true, "Failed to add buffer to page-table pool.");
	}

	if (!mm_ptable_init(&ptable, 0, MM_FLAG_STAGE1, &ppool)) {
		HFTEST_FAIL(true, "Unable to allocate memory for page table.");
	}

	stage1_locked = hftest_mm_get_stage1();
	mm_identity_map(stage1_locked,
			pa_init((uintptr_t)HFTEST_STAGE1_START_ADDRESS),
			pa_init(mm_ptable_addr_space_end(MM_FLAG_STAGE1)),
			MM_MODE_R | MM_MODE_W | MM_MODE_X, &ppool);

	arch_vm_mm_enable(ptable.root);

	return true;
}

bool hftest_mm_get_mode(const void *base, size_t size, uint32_t *mode)
{
	vaddr_t start = va_from_ptr(base);
	vaddr_t end = va_add(start, size);
	struct mm_stage1_locked stage1_locked = hftest_mm_get_stage1();

	assert(mode != NULL);

	return mm_get_mode(stage1_locked.ptable, start, end, mode);
}

void hftest_mm_identity_map(const void *base, size_t size, uint32_t mode)
{
	struct mm_stage1_locked stage1_locked = hftest_mm_get_stage1();
	paddr_t start = pa_from_va(va_from_ptr(base));
	paddr_t end = pa_add(start, size);

	if (mm_identity_map(stage1_locked, start, end, mode, &ppool) != base) {
		FAIL("Could not add new page table mapping. Try increasing "
		     "size of the page table buffer.");
	}
}

void hftest_mm_vcpu_init(void)
{
	arch_vm_mm_enable(ptable.root);
}
