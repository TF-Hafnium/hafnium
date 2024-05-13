/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/ffa.h"

#include "hf/check.h"
#include "hf/ffa.h"
#include "hf/panic.h"
#include "hf/vm_ids.h"

#include "smc.h"

static ffa_id_t spmc_id = HF_INVALID_VM_ID;

/**
 * Returns the SPMC ID returned from the SPMD.
 */
ffa_id_t arch_ffa_spmc_id_get(void)
{
	return spmc_id;
}

/**
 * Initialize the platform FF-A module in the context of running the SPMC.
 * In particular it fetches the SPMC ID to prevent SMC calls everytime
 * FFA_SPM_ID_GET is invoked.
 */
void arch_ffa_init(void)
{
	struct ffa_value ret = plat_ffa_spmc_id_get();

	if (ret.func == FFA_SUCCESS_32) {
		spmc_id = ret.arg2;
	} else if (ret.func == (uint64_t)SMCCC_ERROR_UNKNOWN ||
		   (ret.func == FFA_ERROR_32 &&
		    ffa_error_code(ret) == FFA_NOT_SUPPORTED)) {
		spmc_id = HF_SPMC_VM_ID;
	} else {
		panic("Failed to get SPMC ID\n");
	}

	/*
	 * Check that spmc_id is equal to HF_SPMC_VM_ID.
	 */
	CHECK(spmc_id == HF_SPMC_VM_ID);
}
