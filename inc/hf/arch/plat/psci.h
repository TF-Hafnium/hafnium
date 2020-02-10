/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
