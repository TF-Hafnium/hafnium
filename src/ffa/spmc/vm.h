/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

void ffa_vm_init(void);

struct vm_locked ffa_vm_nwd_create(ffa_id_t vm_id);

void ffa_vm_disable_interrupts(struct vm_locked vm_locked);
