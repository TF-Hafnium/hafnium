/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/other_world.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"

struct ffa_value arch_other_world_call(struct ffa_value args)
{
	dlog_error("Attempted to call TEE function %#lx\n", args.func);
	return ffa_error(FFA_NOT_SUPPORTED);
}
