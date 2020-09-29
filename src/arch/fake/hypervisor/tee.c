/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/tee.h"

#include "hf/dlog.h"
#include "hf/spci.h"
#include "hf/spci_internal.h"

struct spci_value arch_tee_call(struct spci_value args)
{
	dlog_error("Attempted to call TEE function %#x\n", args.func);
	return spci_error(SPCI_NOT_SUPPORTED);
}
