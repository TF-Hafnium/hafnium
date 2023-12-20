/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/types.h"

#include "hf/vcpu.h"

void arch_fpu_save_to_vcpu(struct vcpu *vcpu);
void arch_fpu_regs_save_to_vcpu(struct vcpu *vcpu);
void arch_fpu_state_save_to_vcpu(struct vcpu *vcpu);
void arch_fpu_restore_from_vcpu(struct vcpu *vcpu);
void arch_fpu_regs_restore_from_vcpu(struct vcpu *vcpu);
void arch_fpu_state_restore_from_vcpu(struct vcpu *vcpu);
