/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/timer_mgmt.h"

#include "hf/arch/timer.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/std.h"
#include "hf/vcpu.h"

static void timer_list_add_vcpu(struct cpu *cpu, struct vcpu *vcpu)
{
	struct timer_pending_vcpu_list *timer_list;

	assert(vcpu != NULL && cpu != NULL);

	timer_list = &cpu->pending_timer_vcpus_list;
	sl_lock(&cpu->lock);

	/* Add the vCPU's timer entry if not already part of any list. */
	if (list_empty(&vcpu->timer_node)) {
		/* `root_entry` is also the tail of the timer list. */
		list_prepend(&timer_list->root_entry, &vcpu->timer_node);
	}

	sl_unlock(&cpu->lock);
}

static void timer_list_remove_vcpu(struct cpu *cpu, struct vcpu *vcpu)
{
	assert(vcpu != NULL && cpu != NULL);

	sl_lock(&cpu->lock);
	list_remove(&vcpu->timer_node);
	sl_unlock(&cpu->lock);
}

/**
 * Depending on the state of the vCPU's arch timer, either track or untrack it
 * through the timer list on current CPU.
 */
void timer_vcpu_manage(struct vcpu *vcpu)
{
	assert(vcpu != NULL);

	if (arch_timer_enabled(&vcpu->regs)) {
		/*
		 * Add it to the list maintained by partition manager for this
		 * CPU.
		 */
		timer_list_add_vcpu(vcpu->cpu, vcpu);
	} else {
		timer_list_remove_vcpu(vcpu->cpu, vcpu);
	}
}
