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

#include "sysregs.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/panic.h"
#include "hf/types.h"

#include "msr.h"
#include "perfmon.h"

/**
 * Returns the value for HCR_EL2 for the particular VM.
 * For now, the primary VM has one value and all secondary VMs share a value.
 */
uintreg_t get_hcr_el2_value(spci_vm_id_t vm_id)
{
	uintreg_t hcr_el2_value = 0;

	/* TODO: Determine if we need to set TSW. */
	hcr_el2_value = HCR_EL2_RW | HCR_EL2_TACR | HCR_EL2_TIDCP |
			HCR_EL2_TSC | HCR_EL2_PTW | HCR_EL2_VM;

	if (vm_id != HF_PRIMARY_VM_ID) {
		hcr_el2_value |= HCR_EL2_TWE | HCR_EL2_TWI |
				 HCR_EL2_BSU_INNER_SHAREABLE | HCR_EL2_FB |
				 HCR_EL2_AMO | HCR_EL2_IMO | HCR_EL2_FMO;

		/* TODO: Trap fp access once handler logic is in place. */

		/* TODO: Investigate fpexc32_el2 for 32bit EL0 support. */
	}

	return hcr_el2_value;
}

/**
 * Returns the value for MDCR_EL2 for the particular VM.
 * For now, the primary VM has one value and all secondary VMs share a value.
 */
uintreg_t get_mdcr_el2_value(spci_vm_id_t vm_id)
{
	uintreg_t mdcr_el2_value = read_msr(MDCR_EL2);
	uintreg_t pmcr_el0 = read_msr(PMCR_EL0);

	/*
	 * TODO: Investigate gating settings these values depending on which
	 * features are supported by the current CPU.
	 */

	/*
	 * Preserve E2PB for now, which depends on the SPE implementation.
	 * TODO: Investigate how to detect whether SPE is implemented, and which
	 * stage's translation regime is applicable, i.e., EL2 or EL1.
	 */
	mdcr_el2_value &= MDCR_EL2_E2PB;

	/*
	 * Trap all VM accesses to debug registers for fine-grained control.
	 * Do not trap the Primary VM's debug events, e.g., watchpoint or
	 * breakpoint events (!MDCR_EL2_TDE).
	 */
	mdcr_el2_value |=
		MDCR_EL2_TTRF | MDCR_EL2_TDRA | MDCR_EL2_TDOSA | MDCR_EL2_TDA;

	if (vm_id != HF_PRIMARY_VM_ID) {
		/*
		 * Debug event exceptions should be disabled in secondary VMs
		 * but trap them for additional security.
		 */
		mdcr_el2_value |= MDCR_EL2_TDE;

		/*
		 * Trap secondary VM accesses to performance monitor registers
		 * for fine-grained control.
		 *
		 * Do *not* trap primary VM accesses to performance monitor
		 * registers. Sensitive registers are context switched, and
		 * access to performance monitor registers is more common than
		 * access to debug registers, therefore, trapping them all could
		 * impose a non-trivial overhead.
		 */
		mdcr_el2_value |= MDCR_EL2_TPM | MDCR_EL2_TPMCR;
	}

	/* Disable cycle and event counting at EL2. */
	mdcr_el2_value |= MDCR_EL2_HCCD | MDCR_EL2_HPMD;

	/* All available event counters accessible from all exception levels. */
	mdcr_el2_value |= GET_PMCR_EL0_N(pmcr_el0) & MDCR_EL2_HPMN;

	return mdcr_el2_value;
}
