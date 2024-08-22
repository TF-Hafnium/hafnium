/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/types.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

void hf_ipi_init_interrupt(void);
struct vcpu *hf_ipi_get_pending_target_vcpu(struct cpu *current);
void hf_ipi_send_interrupt(struct vm *vm, ffa_vcpu_index_t target_vcpu_index);
bool hf_ipi_handle(struct vcpu_locked target_vcpu_locked);
