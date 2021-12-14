/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/spinlock.h"

#include "vmapi/hf/ffa.h"

/** The number of bits in each element of the interrupt bitfields. */
#define INTERRUPT_REGISTER_BITS 32

enum vcpu_state {
	/** The vCPU is switched off. */
	VCPU_STATE_OFF,

	/** The vCPU is currently running. */
	VCPU_STATE_RUNNING,

	/** The vCPU is waiting to be allocated CPU cycles to do work. */
	VCPU_STATE_WAITING,

	/**
	 * The vCPU is blocked and waiting for some work to complete on
	 * its behalf.
	 */
	VCPU_STATE_BLOCKED,

	/** The vCPU has been preempted by an interrupt. */
	VCPU_STATE_PREEMPTED,

	/** The vCPU is waiting for an interrupt. */
	VCPU_STATE_BLOCKED_INTERRUPT,

	/** The vCPU has aborted. */
	VCPU_STATE_ABORTED,
};

struct interrupts {
	/** Bitfield keeping track of which interrupts are enabled. */
	uint32_t interrupt_enabled[HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS];
	/** Bitfield keeping track of which interrupts are pending. */
	uint32_t interrupt_pending[HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS];
	/** Bitfield recording the interrupt pin configuration. */
	uint32_t interrupt_type[HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS];
	/**
	 * The number of interrupts which are currently both enabled and
	 * pending. Count independently virtual IRQ and FIQ interrupt types
	 * i.e. the sum of the two counters is the number of bits set in
	 * interrupt_enable & interrupt_pending.
	 */
	uint32_t enabled_and_pending_irq_count;
	uint32_t enabled_and_pending_fiq_count;
};

struct vcpu_fault_info {
	ipaddr_t ipaddr;
	vaddr_t vaddr;
	vaddr_t pc;
	uint32_t mode;
};

struct vcpu {
	struct spinlock lock;

	/*
	 * The state is only changed in the context of the vCPU being run. This
	 * ensures the scheduler can easily keep track of the vCPU state as
	 * transitions are indicated by the return code from the run call.
	 */
	enum vcpu_state state;

	bool is_bootstrapped;
	struct cpu *cpu;
	struct vm *vm;
	struct arch_regs regs;
	struct interrupts interrupts;

	/*
	 * Determine whether the 'regs' field is available for use. This is set
	 * to false when a vCPU is about to run on a physical CPU, and is set
	 * back to true when it is descheduled. This is not relevant for the
	 * primary VM vCPUs in the normal world (or the "other world VM" vCPUs
	 * in the secure world) as they are pinned to physical CPUs and there
	 * is no contention to take care of.
	 */
	bool regs_available;

	/*
	 * If the current vCPU is executing as a consequence of a
	 * FFA_MSG_SEND_DIRECT_REQ invocation, then this member holds the
	 * originating VM ID from which the call originated.
	 * The value HF_INVALID_VM_ID implies the vCPU is not executing as
	 * a result of a prior FFA_MSG_SEND_DIRECT_REQ invocation.
	 */
	ffa_vm_id_t direct_request_origin_vm_id;

	/** Determine whether partition is currently handling managed exit. */
	bool processing_managed_exit;

	/**
	 * Determine whether vCPU is currently handling secure interrupt.
	 */
	bool processing_secure_interrupt;
	bool secure_interrupt_deactivated;

	/**
	 * INTID of the current secure interrupt being processed by this vCPU.
	 */
	uint32_t current_sec_interrupt_id;

	/**
	 * Track current vCPU which got pre-empted when secure interrupt
	 * triggered.
	 */
	struct vcpu *preempted_vcpu;

	/**
	 * Current value of the Priority Mask register which is saved/restored
	 * during secure interrupt handling.
	 */
	uint8_t priority_mask;
};

/** Encapsulates a vCPU whose lock is held. */
struct vcpu_locked {
	struct vcpu *vcpu;
};

/** Container for two vcpu_locked structures. */
struct two_vcpu_locked {
	struct vcpu_locked vcpu1;
	struct vcpu_locked vcpu2;
};

struct vcpu_locked vcpu_lock(struct vcpu *vcpu);
struct two_vcpu_locked vcpu_lock_both(struct vcpu *vcpu1, struct vcpu *vcpu2);
void vcpu_unlock(struct vcpu_locked *locked);
void vcpu_init(struct vcpu *vcpu, struct vm *vm);
void vcpu_on(struct vcpu_locked vcpu, ipaddr_t entry, uintreg_t arg);
ffa_vcpu_index_t vcpu_index(const struct vcpu *vcpu);
bool vcpu_is_off(struct vcpu_locked vcpu);
bool vcpu_secondary_reset_and_start(struct vcpu_locked vcpu_locked,
				    ipaddr_t entry, uintreg_t arg);

bool vcpu_handle_page_fault(const struct vcpu *current,
			    struct vcpu_fault_info *f);

void vcpu_reset(struct vcpu *vcpu);

void vcpu_set_phys_core_idx(struct vcpu *vcpu);

static inline void vcpu_irq_count_increment(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count++;
}

static inline void vcpu_irq_count_decrement(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count--;
}

static inline void vcpu_fiq_count_increment(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count++;
}

static inline void vcpu_fiq_count_decrement(struct vcpu_locked vcpu_locked)
{
	vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count--;
}

static inline uint32_t vcpu_interrupt_irq_count_get(
	struct vcpu_locked vcpu_locked)
{
	return vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count;
}

static inline uint32_t vcpu_interrupt_fiq_count_get(
	struct vcpu_locked vcpu_locked)
{
	return vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count;
}

static inline uint32_t vcpu_interrupt_count_get(struct vcpu_locked vcpu_locked)
{
	return vcpu_locked.vcpu->interrupts.enabled_and_pending_irq_count +
	       vcpu_locked.vcpu->interrupts.enabled_and_pending_fiq_count;
}
