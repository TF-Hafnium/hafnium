/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vcpu.h"

/**
 * Partition manager maintains a list of entries, associated with vCPUs with
 * pending timer deadline, for each CPU. Each list is protected from concurrent
 * accesses, by multiple CPUs, with the help of a spinlock belonging to the CPU
 * owning the list.
 * Note: Each list is maintained as a circular linked list with a special entry
 * called `root_entry`. This entry is not associated with any vCPU and solely
 * exists to help with list manipulation operations. Therefore, if there are
 * five vCPUs with pending timer being tracked by partition manager on a CPU,
 * the corresponding list will have six entries.
 */
struct timer_pending_vcpu_list {
	struct list_entry root_entry;
};

void timer_vcpu_manage(struct vcpu *vcpu);

struct vcpu *timer_find_vcpu_nearest_deadline(struct cpu *cpu);

struct vcpu *timer_find_target_vcpu(struct vcpu *current);

void timer_migrate_to_other_cpu(struct cpu *to_cpu,
				struct vcpu_locked migrate_vcpu_locked);
