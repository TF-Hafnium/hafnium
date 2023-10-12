/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/addr.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/plat/memory_protect.h"

struct ffa_value arch_memory_protect(paddr_t begin, paddr_t end,
				     paddr_t *last_protected_pa)
{
	(void)begin;
	(void)end;
	(void)last_protected_pa;

	return ffa_error(FFA_NOT_SUPPORTED);
}

bool arch_memory_unprotect(paddr_t begin, paddr_t end)
{
	(void)begin;
	(void)end;

	return true;
}
