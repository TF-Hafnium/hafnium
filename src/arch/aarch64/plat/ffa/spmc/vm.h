/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

void plat_ffa_vm_init(struct mpool *ppool);

struct vm_locked plat_ffa_nwd_vm_create(ffa_id_t vm_id);

void plat_ffa_disable_vm_interrupts(struct vm_locked vm_locked);
