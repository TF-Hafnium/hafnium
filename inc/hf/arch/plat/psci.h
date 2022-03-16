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
 * Returns the platform specific PSCI version value.
 */
uint32_t plat_psci_version_get(void);

/**
 * Called once at boot time to initialize the platform power management module.
 */
void plat_psci_init(void);

/**
 * Called before the PSCI_CPU_SUSPEND SMC is forwarded. The power state is
 * provided to allow actions to be taken based on the implementation defined
 * meaning of this field.
 */
void plat_psci_cpu_suspend(uint32_t power_state);

/** Called when a CPU resumes from being off or suspended. */
struct vcpu *plat_psci_cpu_resume(struct cpu *c);
