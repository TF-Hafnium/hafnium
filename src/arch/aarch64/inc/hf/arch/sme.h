/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "msr.h"

static inline uint64_t arch_sme_svcr_get(void)
{
	uint64_t svcr;

	__asm__ volatile(
		".arch_extension sme;"
		"mrs %0, svcr;"
		".arch_extension nosme"
		: "=r"(svcr));

	return svcr & (MSR_SVCR_ZA | MSR_SVCR_SM);
}

static inline void arch_sme_svcr_set(uint64_t svcr)
{
	__asm__ volatile(
		".arch_extension sme;"
		"msr svcr, %0;"
		".arch_extension nosme"
		:
		: "r"(svcr));
}

void arch_sme_enable_traps(void);
void arch_sme_disable_traps(void);
void arch_sme_configure_svl(void);
