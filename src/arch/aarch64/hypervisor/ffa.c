/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/plat/ffa.h"

#include "hf/ffa.h"
#include "hf/panic.h"
#include "hf/vm_ids.h"

/**
 * Returns the SPMC ID returned from the SPMD.
 */
ffa_vm_id_t arch_ffa_spmc_id_get(void)
{
	struct ffa_value ret = plat_ffa_spmc_id_get();

	if (ret.func == FFA_SUCCESS_32) {
		return (ffa_vm_id_t)ret.arg2;
	}
	if (ret.func == FFA_ERROR_32 &&
	    ffa_error_code(ret) != FFA_NOT_SUPPORTED) {
		panic("Failed to get SPMC ID\n");
	}

	return HF_SPMC_VM_ID;
}
