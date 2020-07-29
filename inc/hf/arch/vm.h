/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

/**
 * Set architecture-specific features for the specified VM.
 */
void arch_vm_features_set(struct vm *vm);

/**
 * Return the FF-A partition info VM/SP properties given the VM id.
 */
ffa_partition_properties_t arch_vm_partition_properties(ffa_vm_id_t id);
