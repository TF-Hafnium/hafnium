/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vcpu.h"

#include "msr.h"

/**
 * Returns a reference to the currently executing vCPU.
 */
struct vcpu *arch_vcpu_get_current(void)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	return (struct vcpu *)read_msr(tpidr_el2);
}
