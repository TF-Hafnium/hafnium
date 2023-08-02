/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "../msr.h"
#include "partition_services.h"
#include "test/hftest.h"

struct ffa_value sp_check_cpu_idx_cmd(ffa_id_t test_source,
				      ffa_vcpu_index_t received_cpu_idx)
{
	ffa_id_t own_id = hf_vm_get_id();
	ffa_vcpu_index_t core_idx =
		(ffa_vcpu_index_t)(read_msr(mpidr_el1) & ~0x80000000ULL);

	if (core_idx != received_cpu_idx) {
		return sp_error(own_id, test_source, core_idx);
	}
	return sp_success(own_id, test_source, core_idx);
}
