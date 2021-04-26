/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/vm.h"

struct ffa_value plat_ffa_spmc_id_get(void)
{
	return (struct ffa_value){.func = FFA_ERROR_32,
				  .arg2 = FFA_NOT_SUPPORTED};
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t current_id, const struct vm *target)
{
	(void)current_id;
	(void)target;
	return 0;
}
