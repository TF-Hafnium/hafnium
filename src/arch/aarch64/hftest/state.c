/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/state.h"

#include "msr.h"

void per_cpu_ptr_set(uintptr_t v)
{
	write_msr(tpidr_el1, v);
}

uintptr_t per_cpu_ptr_get(void)
{
	return read_msr(tpidr_el1);
}
