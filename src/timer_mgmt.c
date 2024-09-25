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

/**
 * A vCPU's timer entry is the last entry in the list if it's `next` field
 * points to `root_entry` of the list.
 */
static inline bool timer_is_list_end(struct vcpu *vcpu,
				     struct timer_pending_vcpu_list *timer_list)
{
	return (vcpu->timer_node.next == &timer_list->root_entry);
}

/**
 * Find the vCPU with the nearest timer deadline, being tracked by partition
 * manager, on current CPU.
 */
struct vcpu *timer_find_vcpu_nearest_deadline(struct cpu *cpu)
{
	struct vcpu *vcpu_with_deadline = NULL;
	struct vcpu *it_vcpu = NULL;
	struct timer_pending_vcpu_list *timer_list;
	uint64_t near_deadline = UINT64_MAX;
	struct list_entry *next_timer_entry;

	assert(cpu != NULL);

	timer_list = &cpu->pending_timer_vcpus_list;
	sl_lock(&cpu->lock);

	if (list_empty(&timer_list->root_entry)) {
		goto out;
	}

	next_timer_entry = timer_list->root_entry.next;

	/* Iterate to find the vCPU with nearest deadline. */
	do {
		uint64_t expiry_ns;

		/* vCPU iterator. */
		it_vcpu =
			CONTAINER_OF(next_timer_entry, struct vcpu, timer_node);
		assert(arch_timer_enabled(&it_vcpu->regs));

		expiry_ns = arch_timer_remaining_ns(&it_vcpu->regs);

		if (expiry_ns < near_deadline) {
			near_deadline = expiry_ns;
			vcpu_with_deadline = it_vcpu;
		}

		/* Look at the next entry in the list. */
		next_timer_entry = it_vcpu->timer_node.next;
	} while (!timer_is_list_end(it_vcpu, timer_list));

out:
	sl_unlock(&cpu->lock);
	return vcpu_with_deadline;
}

/**
 * Find the vCPU whose timer deadline has expired and needs to be resumed at
 * the earliest.
 */
struct vcpu *timer_find_target_vcpu(struct vcpu *current)
{
	struct vcpu *target_vcpu;

	if (current->vm->id == HF_OTHER_WORLD_ID) {
		target_vcpu = timer_find_vcpu_nearest_deadline(current->cpu);
	} else {
		target_vcpu = current;
	}

	return target_vcpu;
}
