/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/tee.h"

#include "hf/spci.h"

#include "smc.h"

struct spci_value arch_tee_call(struct spci_value args)
{
	return smc_forward(args.func, args.arg1, args.arg2, args.arg3,
			   args.arg4, args.arg5, args.arg6, args.arg7);
}
