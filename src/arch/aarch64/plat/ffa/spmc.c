/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "smc.h"

struct ffa_value plat_ffa_spmc_id_get(void)
{
	/*
	 * Since we are running in the SPMC use FFA_ID_GET to fetch our
	 * ID from the SPMD.
	 */
	return smc_ffa_call((struct ffa_value){.func = FFA_ID_GET_32});
}
