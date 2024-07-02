/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "hf/arch/types.h"

enum power_status {
	POWER_STATUS_ON,
	POWER_STATUS_OFF,
	POWER_STATUS_ON_PENDING,
};

/*
 * The type of CPU entry points: a function that takes one `uintreg_t` argument
 * and returns `void`.
 */
typedef void(arch_cpu_entry_point)(uintreg_t arg);

/**
 * Holds temporary state used to set up the environment on which CPUs will
 * start executing.
 *
 * vm_cpu_entry() depends on the layout of this struct.
 */
struct arch_cpu_start_state {
	uintptr_t initial_sp;
	arch_cpu_entry_point *entry;
	uintreg_t arg;
};

bool arch_cpu_start(uintptr_t id, struct arch_cpu_start_state *s);

noreturn void arch_cpu_stop(void);
enum power_status arch_cpu_status(cpu_id_t cpu_id);

noreturn void arch_power_off(void);
noreturn void arch_reboot(void);
