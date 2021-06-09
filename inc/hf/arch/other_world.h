/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/vm.h"

bool arch_other_world_vm_init(struct vm *other_world_vm, struct mpool *ppool);
struct ffa_value arch_other_world_call(struct ffa_value args);
