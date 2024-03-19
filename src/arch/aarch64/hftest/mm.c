/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mm.h"

#include "hf/arch/barriers.h"
#include "hf/arch/vm/mm.h"

#include "hf/dlog.h"

#include "../msr.h"

#define STAGE1_DEVICEINDX UINT64_C(0)
#define STAGE1_NORMALINDX UINT64_C(1)

static uintreg_t mm_mair_el1;
static uintreg_t mm_tcr_el1;
static uintreg_t mm_sctlr_el1;

static uintreg_t mm_reset_ttbr0_el1;
static uintreg_t mm_reset_mair_el1;
static uintreg_t mm_reset_tcr_el1;
static uintreg_t mm_reset_sctlr_el1;

/* For hftest, limit Stage1 PA range to 512GB (1 << 39) */
#define HFTEST_S1_PA_BITS (39)

/**
 * Initialize MMU for a test running in EL1.
 */
bool arch_vm_mm_init(void)
{
	uint64_t mm_features = read_msr(id_aa64mmfr0_el1);
	uint64_t pa_range = arch_mm_get_pa_range();
	uint32_t pa_bits = arch_mm_get_pa_bits(pa_range);

	/* Check that 4KB granules are supported. */
	if (((mm_features >> 28) & 0xf) == 0xf) {
		dlog_error("4KB granules are not supported\n");
		return false;
	}

	/* Check the physical address range. */
	if (!pa_bits) {
		dlog_error(
			"Unsupported value of id_aa64mmfr0_el1.PARange: %lx\n",
			pa_range);
		return false;
	}

	/*
	 * Limit PA bits to HFTEST_S1_PA_BITS. Using the pa_bits reported by
	 * arch_mm_get_pa_range requires an increase in page pool size.
	 */
	arch_mm_stage1_max_level_set(HFTEST_S1_PA_BITS);

	/*
	 * Preserve initial values of the system registers in case we want to
	 * reset them.
	 */
	mm_reset_ttbr0_el1 = read_msr(ttbr0_el1);
	mm_reset_mair_el1 = read_msr(mair_el1);
	mm_reset_tcr_el1 = read_msr(tcr_el1);
	mm_reset_sctlr_el1 = read_msr(sctlr_el1);

	/*
	 * 0    -> Device-nGnRnE memory
	 * 0xff -> Normal memory, Inner/Outer Write-Back Non-transient,
	 *         Write-Alloc, Read-Alloc.
	 */
	mm_mair_el1 = (0ULL << (8 * STAGE1_DEVICEINDX)) |
		      (0xffULL << (8 * STAGE1_NORMALINDX));

	mm_tcr_el1 = (0ULL << 37) |	/* disable TBI0, top byte ignored. */
		     (pa_range << 32) | /* PS. */
		     (0ULL << 14) |	/* TG0, granule size, 4KB. */
		     (3ULL << 12) |	/* SH0, inner shareable. */
		     (1ULL << 10) | /* ORGN0, normal mem, WB RA WA Cacheable. */
		     (1ULL << 8) |  /* IRGN0, normal mem, WB RA WA Cacheable. */
		     (64 - HFTEST_S1_PA_BITS) | /* T0SZ, 2^hftest_s1_pa_bits */
		     0ULL;

	mm_sctlr_el1 = (1ULL << 0) |  /* M, enable stage 1 EL2 MMU. */
		       (1ULL << 2) |  /* C, data cache enable. */
		       (1ULL << 3) |  /* SA, enable stack alignment check. */
		       (1ULL << 12) | /* I, instruction cache enable. */
		       (0ULL << 19) | /* WXN bit, writable execute never. */
		       (1ULL << 31) | /* EnIA */
		       0ULL;
	return true;
}

void arch_vm_mm_enable(paddr_t table)
{
	/* Configure translation management registers. */
	write_msr(ttbr0_el1, pa_addr(table));
	write_msr(mair_el1, mm_mair_el1);
	write_msr(tcr_el1, mm_tcr_el1);

	/* Configure sctlr_el1 to enable MMU and cache. */
	dsb(sy);
	isb();
	write_msr(sctlr_el1, mm_sctlr_el1);
	isb();
}

void arch_vm_mm_reset(void)
{
	/* Set system registers to their reset values. */
	write_msr(ttbr0_el1, mm_reset_ttbr0_el1);
	write_msr(mair_el1, mm_reset_mair_el1);
	write_msr(tcr_el1, mm_reset_tcr_el1);

	dsb(sy);
	isb();
	write_msr(sctlr_el1, mm_reset_sctlr_el1);
	isb();
}
