/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vcpu.h"

/**
 * Called before the PSCI_CPU_SUSPEND SMC is forwarded. The power state is
 * provided to allow actions to be taken based on the implementation defined
 * meaning of this field.
 */
void plat_psci_cpu_suspend(uint32_t power_state);

/** Called when a CPU resumes from being off or suspended. */
void plat_psci_cpu_resume(void);
