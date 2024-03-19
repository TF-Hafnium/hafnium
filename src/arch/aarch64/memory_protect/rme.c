/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/addr.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/plat/memory_protect.h"

#include "vmapi/hf/ffa.h"

#include "smc.h"
#include "sysregs.h"

/**
 * Leverages RME feature to dynamically change the PAS at a given range.
 */
struct ffa_value arch_memory_protect(paddr_t begin, paddr_t end,
				     paddr_t *last_protected_pa)
{
	uintptr_t size = pa_difference(begin, end);
	struct ffa_value ret;

	if (!is_arch_feat_rme_supported()) {
		dlog_verbose(
			"%s: memory protect services rely on RME feature. "
			"Memory is not protected %lx\n",
			__func__, pa_addr(begin));
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	ret = smc_ffa_call((struct ffa_value){.func = PLAT_PROTECT_MEM_64,
					      .arg1 = pa_addr(begin),
					      .arg2 = size});

	switch (ret.func) {
	case SMCCC_OK:
		/* Protect call ended with success. */
		break;
	case SMCCC_DENIED: {
		/* Denied the operation due to state of memory. */
		paddr_t last_protected = pa_init(ret.arg1);

		dlog_verbose("%s: denied to update PAS. Last: %lx\n", __func__,
			     pa_addr(last_protected));

		/* If PAS update failed from first region. */
		if (last_protected_pa != NULL) {
			*last_protected_pa = last_protected;
		}

		return ffa_error(FFA_DENIED);
	}
	case SMCCC_INVALID:
		/* Invalid parameters. */
		dlog_verbose(
			"%s: invalid values for protecting memory at "
			"the monitor.\n",
			__func__);
		return ffa_error(FFA_INVALID_PARAMETERS);
	default:
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

bool arch_memory_unprotect(paddr_t begin, paddr_t end)
{
	uintptr_t size = pa_difference(begin, end);
	struct ffa_value ret;

	/*
	 * In case the RME feature is not supported, the protect call should
	 * have failed with error FFA_NOT_SUPPORTED.
	 * As such, memory was never protected in the first place, so there
	 * shouldn't be a call to unprotect it.
	 */
	assert(is_arch_feat_rme_supported());

	ret = smc_ffa_call((struct ffa_value){.func = PLAT_UNPROTECT_MEM_64,
					      .arg1 = pa_addr(begin),
					      .arg2 = size});

	return ret.func == SMCCC_OK;
}
