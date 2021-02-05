/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/cpu.h"
#include "hf/offset_size_header.h"
#include "hf/vm.h"

DEFINE_OFFSETOF(CPU_ID, struct cpu, id)
DEFINE_OFFSETOF(CPU_STACK_BOTTOM, struct cpu, stack_bottom)
DEFINE_OFFSETOF(VCPU_VM, struct vcpu, vm)
DEFINE_OFFSETOF(VCPU_REGS, struct vcpu, regs)
DEFINE_OFFSETOF(VCPU_LAZY, struct vcpu, regs.lazy)
DEFINE_OFFSETOF(VCPU_FREGS, struct vcpu, regs.fp)

DEFINE_OFFSETOF(VM_ID, struct vm, id)

#if GIC_VERSION == 3 || GIC_VERSION == 4
DEFINE_OFFSETOF(VCPU_GIC, struct vcpu, regs.gic)
#endif
