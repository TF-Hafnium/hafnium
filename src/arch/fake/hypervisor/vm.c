/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm.h"

ffa_partition_properties_t arch_vm_partition_properties(ffa_vm_id_t id)
{
	(void)id;

	return 0;
}
