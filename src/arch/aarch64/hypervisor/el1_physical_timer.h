/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/types.h"

#include "hf/cpu.h"

#include "vmapi/hf/ffa.h"

bool el1_physical_timer_is_register_access(uintreg_t esr);

bool el1_physical_timer_process_access(struct vcpu *vcpu, uintreg_t esr);
