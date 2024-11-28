/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/power_management.h"

/**
 * Returns FFA_SUCCESS as FFA_SECONDARY_EP_REGISTER is supported at the
 * secure virtual FF-A instance.
 */
bool plat_ffa_is_secondary_ep_register_supported(void)
{
	return true;
}
