/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"

#include "hf/dlog.h"
#include "hf/ffa/vm.h"
#include "hf/mpool.h"

void ffa_init_log(void)
{
	dlog_info("Initializing Hafnium (SPMC)\n");
}

void ffa_init(struct mpool *ppool)
{
	arch_ffa_init();
	ffa_vm_init(ppool);
}

void ffa_init_set_tee_enabled(bool tee_enabled)
{
	(void)tee_enabled;
}

void ffa_init_version(void)
{
	/*
	 * This stub is intentionally empty since SPMC does not have to
	 * negotiate its version with other world. Hence, no need to invoke
	 * FFA_VERSION at this instance.
	 */
}
