/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/types.h"

#include "hf/cpu.h"

#include "vmapi/hf/ffa.h"

/**
 * Set to disable cycle counting when event counting is prohibited.
 */
#define PMCR_EL0_DP 0x10

/**
 * Set to enable export of events where not prohibited.
 */
#define PMCR_EL0_X 0x8

/**
 * Set to enable event counting.
 */
#define PMCR_EL0_E 0x1

/**
 * Set to disable cycle counting in EL1.
 */
#define PMCCFILTR_EL0_P 0x80000000

/**
 * Set to disable cycle counting in EL0.
 */
#define PMCCFILTR_EL0_U 0x40000000

/**
 * Cycle counting in non-secure EL1 is enabled if NSK == P.
 */
#define PMCCFILTR_EL0_NSK 0x20000000

/**
 * Cycle counting in non-secure EL0 is enabled if NSU == U.
 */
#define PMCCFILTR_EL0_NSU 0x10000000

/**
 * Set to enable cycle counting in EL2.
 */
#define PMCCFILTR_EL0_NSH 0x8000000

/**
 * Cycle counting in EL3 is enabled if M == P.
 */
#define PMCCFILTR_EL0_M 0x4000000

/**
 * Cycle counting in Secutre EL2 is enabled if SH != NSH.
 */
#define PMCCFILTR_EL0_SH 0x1000000

bool perfmon_is_register_access(uintreg_t esr_el2);

bool perfmon_process_access(struct vcpu *vcpu, ffa_id_t vm_id,
			    uintreg_t esr_el2);

uintreg_t perfmon_get_pmccfiltr_el0_init_value(ffa_id_t vm_id);
