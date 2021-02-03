/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "hf/vm_ids.h"

ffa_vm_id_t arch_ffa_spmc_id_get(void)
{
	return HF_SPMC_VM_ID;
}
