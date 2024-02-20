/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mm.h"

/** Arch-specific information about a VM. */
struct arch_vm {
	/**
	 * The index of the last vCPU of this VM which ran on each pCPU. Each
	 * element of this array should only be read or written by code running
	 * on that CPU, which avoids contention and so no lock is needed to
	 * access this field.
	 */
	ffa_vcpu_index_t last_vcpu_on_cpu[MAX_CPUS];
	arch_features_t trapped_features;

	/*
	 * Masks for feature registers trappable by HCR_EL2.TID3.
	 */
	struct {
		uintreg_t id_aa64mmfr1_el1;
		uintreg_t id_aa64pfr0_el1;
		uintreg_t id_aa64pfr1_el1;
		uintreg_t id_aa64dfr0_el1;
		uintreg_t id_aa64isar1_el1;
	} tid3_masks;

#if SECURE_WORLD == 1
	/**
	 * struct vm ptable is root page table pointed to by:
	 * - VTTBR_EL2 for the Hypervisor defining the VM non-secure IPA space.
	 * - VSTTBR_EL2 for the SPMC defining the SP secure IPA space.
	 * ptable_ns is root page table pointed to by VTTBR_EL2 for
	 * the SPMC defining the SP non-secure IPA space.
	 */
	struct mm_ptable ptable_ns;

	/**
	 * Set of page tables used for definiting the peripheral's non-secure
	 * IPA space, in the context of SPMC.
	 */
	struct mm_ptable iommu_ptables_ns[PARTITION_MAX_DMA_DEVICES];
#endif
};
