/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "hf/arch/types.h"

#include "hf/cpu.h"

#include "vmapi/hf/spci.h"

/**
 * RT value that indicates an access to register XZR (always 0).
 * See Arm Architecture Reference Manual Armv8-A, C1.2.5
 */
#define RT_REG_XZR (31)

/**
 * Hypervisor (EL2) Cycle Count Disable.
 */
#define MDCR_EL2_HCCD (0x1u << 23)

/**
 * Controls traps for Trace Filter.
 */
#define MDCR_EL2_TTRF (0x1u << 19)

/**
 * Hypervisor (EL2) Event Count Disable.
 */
#define MDCR_EL2_HPMD (0x1u << 17)

/**
 * Controls the owning translation regime and access to Profiling Buffer control
 * registers from EL1. Depends on whether SPE is implemented.
 */
#define MDCR_EL2_E2PB (0x3u << 12)

/**
 * Controls traps for Debug ROM.
 */
#define MDCR_EL2_TDRA (0x1u << 11)

/**
 * Controls traps for OS-Related Register Access.
 */
#define MDCR_EL2_TDOSA (0x1u << 10)

/**
 * Controls traps for remaining Debug Registers not trapped by TDRA and TDOSA.
 */
#define MDCR_EL2_TDA (0x1u << 9)

/**
 * Controls traps for all debug exceptions (e.g., breakpoints).
 */
#define MDCR_EL2_TDE (0x1u << 8)

/**
 * Controls traps for all PMU register accesses other than PMCR_EL0.
 */
#define MDCR_EL2_TPM (0x1u << 6)

/**
 * Controls traps for PMU register PMCR_EL0.
 */
#define MDCR_EL2_TPMCR (0x1u << 5)

/**
 * Defines the number of event counters that are accessible from various
 * exception levels, if permitted.  Dependant on whether PMUv3 is implemented.
 */
#define MDCR_EL2_HPMN (0x1fu << 0)

/**
 * System register are identified by op0, op2, op1, crn, crm. The ISS encoding
 * includes also rt and direction. Exclude them,  @see D13.2.37 (D13-2977).
 */
#define ISS_SYSREG_MASK                                \
	(((1u << 22) - 1u) & /* Select the ISS bits */ \
	 ~(0x1fu << 5) &     /* exclude rt */          \
	 ~1u /* exclude direction */)

#define GET_ISS_SYSREG(esr) (ISS_SYSREG_MASK & (esr))

/**
 * Op0 from the ISS encoding in the ESR.
 */
#define ISS_OP0_MASK 0x300000
#define ISS_OP0_SHIFT 20
#define GET_ISS_OP0(esr) ((ISS_OP0_MASK & (esr)) >> ISS_OP0_SHIFT)

/**
 * Op1 from the ISS encoding in the ESR.
 */
#define ISS_OP1_MASK 0x1c000
#define ISS_OP1_SHIFT 14
#define GET_ISS_OP1(esr) ((ISS_OP1_MASK & (esr)) >> ISS_OP1_SHIFT)

/**
 * Op2 from the ISS encoding in the ESR.
 */
#define ISS_OP2_MASK 0xe0000
#define ISS_OP2_SHIFT 17
#define GET_ISS_OP2(esr) ((ISS_OP2_MASK & (esr)) >> ISS_OP2_SHIFT)

/**
 * CRn from the ISS encoding in the ESR.
 */
#define ISS_CRN_MASK 0x3c00
#define ISS_CRN_SHIFT 10
#define GET_ISS_CRN(esr) ((ISS_CRN_MASK & (esr)) >> ISS_CRN_SHIFT)

/**
 * CRm from the ISS encoding in the ESR.
 */
#define ISS_CRM_MASK 0x1e
#define ISS_CRM_SHIFT 1
#define GET_ISS_CRM(esr) ((ISS_CRM_MASK & (esr)) >> ISS_CRM_SHIFT)

/**
 * Rt, which identifies the general purpose register used for the operation.
 */
#define ISS_RT_MASK 0x3e0
#define ISS_RT_SHIFT 5
#define GET_ISS_RT(esr) ((ISS_RT_MASK & (esr)) >> ISS_RT_SHIFT)

/**
 * Direction (i.e., read (1) or write (0), is the first bit in the ISS/ESR.
 */
#define ISS_DIRECTION_MASK 1u

/**
 * Gets the direction of the system register access, read (1) or write (0).
 */
#define GET_ISS_DIRECTION(esr) (ISS_DIRECTION_MASK & (esr))

/**
 * True if the ISS encoded in the esr indicates a read of the system register.
 */
#define ISS_IS_READ(esr) (ISS_DIRECTION_MASK & (esr))

/**
 * Returns the ISS encoding given the various instruction encoding parameters.
 */
#define GET_ISS_ENCODING(op0, op1, crn, crm, op2)          \
	((op0) << ISS_OP0_SHIFT | (op2) << ISS_OP2_SHIFT | \
	 (op1) << ISS_OP1_SHIFT | (crn) << ISS_CRN_SHIFT | \
	 (crm) << ISS_CRM_SHIFT)

#define PMCR_EL0_N_MASK 0xf800
#define PMCR_EL0_N_SHIFT 11
#define GET_PMCR_EL0_N(pmcr) ((PMCR_EL0_N_MASK & (pmcr)) >> PMCR_EL0_N_SHIFT)

uintreg_t get_mdcr_el2_value(spci_vm_id_t vm_id);
