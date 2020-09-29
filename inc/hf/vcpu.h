/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"
#include "hf/spinlock.h"

#include "vmapi/hf/spci.h"

/** The number of bits in each element of the interrupt bitfields. */
#define INTERRUPT_REGISTER_BITS 32

enum vcpu_state {
	/** The vCPU is switched off. */
	VCPU_STATE_OFF,

	/** The vCPU is ready to be run. */
	VCPU_STATE_READY,

	/** The vCPU is currently running. */
	VCPU_STATE_RUNNING,

	/** The vCPU is waiting for a message. */
	VCPU_STATE_BLOCKED_MAILBOX,

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
	/**
	 * The number of interrupts which are currently both enabled and
	 * pending. i.e. the number of bits set in interrupt_enable &
	 * interrupt_pending.
	 */
	uint32_t enabled_and_pending_count;
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

	struct cpu *cpu;
	struct vm *vm;
	struct arch_regs regs;
	struct interrupts interrupts;

	/*
	 * Determine whether the 'regs' field is available for use. This is set
	 * to false when a vCPU is about to run on a physical CPU, and is set
	 * back to true when it is descheduled.
	 */
	bool regs_available;

	/*
	 * If the current vCPU is executing as a consequence of a
	 * SPCI_MSG_SEND_DIRECT_REQ this member points to the vCPU where the
	 * call originated. A NULL value implies the vCPU is not executing on
	 * the context of a SPCI_MSG_SEND_DIRECT_REQ.
	 */
	struct vcpu *direct_request_origin_vcpu;
};

/** Encapsulates a vCPU whose lock is held. */
struct vcpu_locked {
	struct vcpu *vcpu;
};

struct vcpu_locked vcpu_lock(struct vcpu *vcpu);
void vcpu_unlock(struct vcpu_locked *locked);
void vcpu_init(struct vcpu *vcpu, struct vm *vm);
void vcpu_on(struct vcpu_locked vcpu, ipaddr_t entry, uintreg_t arg);
spci_vcpu_index_t vcpu_index(const struct vcpu *vcpu);
bool vcpu_is_off(struct vcpu_locked vcpu);
bool vcpu_secondary_reset_and_start(struct vcpu *vcpu, ipaddr_t entry,
				    uintreg_t arg);

bool vcpu_handle_page_fault(const struct vcpu *current,
			    struct vcpu_fault_info *f);
