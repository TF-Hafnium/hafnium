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

#include "msr.h"

/**
 * Returns the value for HCR_EL2 for the particular VM.
 * For now, the primary VM has one value and all secondary VMs share a value.
 */
uintreg_t get_hcr_el2_value(spci_vm_id_t vm_id)
{
	uintreg_t hcr_el2_value = 0;

	/* Baseline values for all VMs. */

	/*
	 * Trap access to registers in ID group 3. These registers report on
	 * the underlying support for CPU features. Because Hafnium restricts
	 * certain features, e.g., RAS, it should emulate access to these
	 * registers to report the correct set of features supported.
	 */
	hcr_el2_value |= HCR_EL2_TID3;

	/* Execution state for EL1 is AArch64. */
	hcr_el2_value |= HCR_EL2_RW;

	/* Trap implementation registers and functionality. */
	hcr_el2_value |= HCR_EL2_TACR | HCR_EL2_TIDCP;

	/* Trap SMC instructions. */
	hcr_el2_value |= HCR_EL2_TSC;

	/*
	 * Translation table access made as part of a stage 1 translation
	 * table walk is subject to a stage 2 translation;
	 */
	hcr_el2_value |= HCR_EL2_PTW;

	/* Enable stage 2 address translation;*/
	hcr_el2_value |= HCR_EL2_VM;

	/* Trap cache maintenance instructions that operate by Set/Way. */
	hcr_el2_value |= HCR_EL2_TSW;

	/* Do *not* trap PAuth. APK and API bits *disable* trapping when set. */
	hcr_el2_value |= HCR_EL2_APK | HCR_EL2_API;

	/* Baseline values for all secondary VMs. */
	if (vm_id != HF_PRIMARY_VM_ID) {
		/*
		 * Set the minimum shareability domain to barrier instructions
		 * as inner shareable.
		 */
		hcr_el2_value |= HCR_EL2_BSU_INNER_SHAREABLE;

		/*
		 * Broadcast instructions related to invalidating the TLB within
		 * the Inner Shareable domain.
		 */
		hcr_el2_value |= HCR_EL2_FB;

		/* Route physical SError/IRQ/FIQ interrupts to EL2. */
		hcr_el2_value |= HCR_EL2_AMO | HCR_EL2_IMO | HCR_EL2_FMO;

		/* Trap wait for event/interrupt instructions. */
		hcr_el2_value |= HCR_EL2_TWE | HCR_EL2_TWI;
	}

	return hcr_el2_value;
}

/**
 * Returns the default value for MDCR_EL2.
 */
uintreg_t get_mdcr_el2_value(void)
{
	uintreg_t mdcr_el2_value = read_msr(MDCR_EL2);
	uintreg_t pmcr_el0 = read_msr(PMCR_EL0);

	/* Baseline values for all VMs. */

	/* Disable cycle and event counting at EL2. */
	mdcr_el2_value |= MDCR_EL2_HCCD | MDCR_EL2_HPMD;

	/* All available event counters accessible from all exception levels. */
	mdcr_el2_value |= GET_PMCR_EL0_N(pmcr_el0) & MDCR_EL2_HPMN;

	return mdcr_el2_value;
}

/**
 * Returns the value for CPTR_EL2 for the CPU.
 */
uintreg_t get_cptr_el2_value(void)
{
	return CPTR_EL2_TTA;
}
