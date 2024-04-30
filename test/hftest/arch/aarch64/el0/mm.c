/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/mm.h"

struct mm_stage1_locked hftest_mm_get_stage1(void)
{
	return (struct mm_stage1_locked){.ptable = NULL};
}

struct mpool *hftest_mm_get_ppool(void)
{
	return NULL;
}

bool hftest_mm_init(void)
{
	return true;
}

// NOLINTNEXTLINE
bool hftest_mm_get_mode(const void *base, size_t size, uint32_t *mode)
{
	(void)base;
	(void)size;
	(void)mode;

	return true;
}

void hftest_mm_identity_map(const void *base, size_t size, uint32_t mode)
{
	(void)base;
	(void)size;
	(void)mode;
}

void hftest_mm_vcpu_init(void)
{
}
