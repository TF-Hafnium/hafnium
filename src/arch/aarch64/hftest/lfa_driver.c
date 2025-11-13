/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/lfa_helpers.h"

#include "vmapi/hf/call.h"

#include "smc.h"

/**
 * Determine the version of the LFA ABI implemented.
 */
uint64_t lfa_get_version(void)
{
	struct ffa_value smc_res;

	smc_res = smc64(LFA_VERSION, 0, 0, 0, 0, 0, 0, 0);

	return smc_res.func;
}

/**
 * Determine if a specific LFA ABI is supported.
 */
bool lfa_is_feature_supported(uint32_t func_id)
{
	struct ffa_value smc_res;

	smc_res = smc64(LFA_FEATURES, func_id, 0, 0, 0, 0, 0, 0);

	return smc_res.func == LFA_SUCCESS;
}

/**
 * Returns the total number of platform firmware components.
 */
uint32_t lfa_get_info(void)
{
	struct ffa_value smc_res;

	if (!lfa_is_feature_supported(LFA_GET_INFO)) {
		return 0U;
	}

	smc_res = smc64(LFA_GET_INFO, 0, 0, 0, 0, 0, 0, 0);

	if (smc_res.func != LFA_SUCCESS) {
		return 0U;
	}

	return (uint32_t)smc_res.arg1;
}

/**
 * Discover the properties of the specified firmware component managed by LFA.
 */
struct ffa_value lfa_get_inventory(uint32_t component_id)
{
	struct ffa_value smc_res = {
		.func = LFA_NOT_SUPPORTED,
	};

	if (lfa_is_feature_supported(LFA_GET_INVENTORY)) {
		smc_res = smc64(LFA_GET_INVENTORY, component_id, 0, 0, 0, 0, 0,
				0);
	}

	return smc_res;
}

struct ffa_value lfa_prime(uint32_t component_id)
{
	struct ffa_value smc_res = {
		.func = LFA_NOT_SUPPORTED,
	};

	if (lfa_is_feature_supported(LFA_PRIME)) {
		smc_res = smc64(LFA_PRIME, component_id, 0, 0, 0, 0, 0, 0);
	}

	return smc_res;
}

enum lfa_return_code lfa_activate(uint32_t component_id, uint32_t flags,
				  uintptr_t entry_point_addr,
				  uint64_t context_id)
{
	struct ffa_value smc_res;

	smc_res = smc64(LFA_ACTIVATE, component_id, flags, entry_point_addr,
			context_id, 0, 0, 0);

	return (uint32_t)smc_res.func;
}

enum lfa_return_code lfa_cancel(uint32_t component_id)
{
	struct ffa_value smc_res;

	smc_res = smc64(LFA_CANCEL, component_id, 0, 0, 0, 0, 0, 0);

	return (uint32_t)smc_res.func;
}
