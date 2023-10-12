/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/addr.h"

/*
 * SMC IDs used to update the security of the memory being shared from the NWd
 * to the SWd.
 */
#define PLAT_PROTECT_MEM_64 UINT32_C(0xC2000101)
#define PLAT_UNPROTECT_MEM_64 UINT32_C(0xC2000102)

struct ffa_value arch_memory_protect(paddr_t begin, paddr_t end,
				     paddr_t *last_protected_pa);

bool arch_memory_unprotect(paddr_t begin, paddr_t end);
