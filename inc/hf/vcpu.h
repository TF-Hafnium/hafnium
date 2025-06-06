/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/types.h"

#include "hf/addr.h"
#include "hf/interrupt_desc.h"
#include "hf/list.h"
#include "hf/mm.h"
#include "hf/spinlock.h"

#include "vmapi/hf/ffa.h"

/** Action for non secure interrupt by SPMC. */
#define NS_ACTION_QUEUED 0
#define NS_ACTION_ME 1
#define NS_ACTION_SIGNALED 2

/** Maximum number of pending virtual interrupts in the queue per vCPU. */
#define VINT_QUEUE_MAX 10

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

/** Refer to section 7 of the FF-A v1.1 EAC0 spec. */
enum partition_runtime_model {
	RTM_NONE,
	/** Runtime model for FFA_RUN. */
	RTM_FFA_RUN,
	/** Runtime model for FFA_MSG_SEND_DIRECT_REQUEST. */
	RTM_FFA_DIR_REQ,
	/** Runtime model for Secure Interrupt handling. */
	RTM_SEC_INTERRUPT,
	/** Runtime model for SP Initialization. */
	RTM_SP_INIT,
};

/** Refer to section 8.2.3 of the FF-A EAC0 spec. */
enum schedule_mode {
	NONE,
	/** Normal world scheduled mode. */
	NWD_MODE,
	/** SPMC scheduled mode. */
	SPMC_MODE,
};

enum power_mgmt_operation {
	PWR_MGMT_NONE = 0,
	/** Power off the CPU. */
	PWR_MGMT_CPU_OFF,
	/** No other operations are supported at the moment. */
};

/*
 * This queue is implemented as a circular buffer. The entries are managed on
 * a First In First Out basis.
 */
struct interrupt_queue {
	uint32_t vint_buffer[VINT_QUEUE_MAX];
	uint16_t head;
	uint16_t tail;
	size_t queued_vint_count;
};

struct interrupts {
	/** Bitfield keeping track of which interrupts are enabled. */
	struct interrupt_bitmap interrupt_enabled;
	/** Bitfield keeping track of which interrupts are pending. */
	struct interrupt_bitmap interrupt_pending;
	/** Bitfield recording the interrupt pin configuration. */
	struct interrupt_bitmap interrupt_type;
	/**
	 * The number of interrupts which are currently both enabled and
	 * pending. Count independently virtual IRQ and FIQ interrupt types
	 * i.e. the sum of the two counters is the number of bits set in
	 * interrupt_enable & interrupt_pending.
	 */
	uint32_t enabled_and_pending_irq_count;
	uint32_t enabled_and_pending_fiq_count;

	/**
	 * Partition Manager maintains a queue of pending virtual interrupts.
	 */
	struct interrupt_queue vint_q;
};

struct vcpu_fault_info {
	ipaddr_t ipaddr;
	vaddr_t vaddr;
	vaddr_t pc;
	mm_mode_t mode;
};

struct call_chain {
	/** Previous node in the SP call chain. */
	struct vcpu *prev_node;

	/** Next node in the SP call chain. */
	struct vcpu *next_node;
};

#define LOG_BUFFER_SIZE 256

struct log_buffer {
	char chars[LOG_BUFFER_SIZE];
	uint16_t len;
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

	struct log_buffer log_buffer;

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
	 * direct request invocation, then this member holds the
	 * originating VM ID from which the call originated.
	 * The value HF_INVALID_VM_ID implies the vCPU is not executing as
	 * a result of a prior direct request invocation.
	 */
	struct {
		ffa_id_t vm_id;
		/** Indicate whether request is via FFA_MSG_SEND_DIRECT_REQ2. */
		bool is_ffa_req2;
		/** Indicate whether request is a framework message. */
		bool is_framework;
	} direct_request_origin;

	/** Determine whether partition is currently handling managed exit. */
	bool processing_managed_exit;

	/**
	 * Track current vCPU which got pre-empted when secure interrupt
	 * triggered.
	 */
	struct vcpu *preempted_vcpu;

	/** SP call chain. */
	struct call_chain call_chain;

	/**
	 * Track if pending interrupts have been retrieved by
	 * FFA_NOTIFICATION_INFO_GET.
	 */
	bool interrupts_info_get_retrieved;

	/**
	 * Indicates if the current vCPU is running in SPMC scheduled
	 * mode or Normal World scheduled mode.
	 */
	enum schedule_mode scheduling_mode;

	/**
	 * If the action in response to a non-secure or other-secure interrupt
	 * is to queue it, this field is used to save and restore the current
	 * priority mask.
	 */
	uint8_t prev_interrupt_priority;

	/** Partition Runtime Model. */
	enum partition_runtime_model rt_model;

	/**
	 * An entry in a list maintained by Hafnium for pending arch timers.
	 * It exists in the list on behalf of its parent vCPU. The `prev` and
	 * `next` fields point to the adjacent entries in the list. The list
	 * itself is protected by a spinlock therefore timer entry is
	 * safeguarded from concurrent accesses.
	 */
	struct list_entry timer_node;

	/*
	 * List entry pointing to the next vcpu with an IPI pending on the
	 * same pinned CPU.
	 */
	struct list_entry ipi_list_node;

	/*
	 * Denotes which power management operation message is being currently
	 * handled by this vCPU.
	 */
	enum power_mgmt_operation pwr_mgmt_op;
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

void vcpu_set_phys_core_idx(struct vcpu *vcpu);
void vcpu_set_boot_info_gp_reg(struct vcpu *vcpu);

static inline void vcpu_call_chain_extend(struct vcpu_locked vcpu1_locked,
					  struct vcpu_locked vcpu2_locked)
{
	vcpu1_locked.vcpu->call_chain.next_node = vcpu2_locked.vcpu;
	vcpu2_locked.vcpu->call_chain.prev_node = vcpu1_locked.vcpu;
}

static inline void vcpu_call_chain_remove_node(struct vcpu_locked vcpu1_locked,
					       struct vcpu_locked vcpu2_locked)
{
	vcpu1_locked.vcpu->call_chain.prev_node = NULL;
	vcpu2_locked.vcpu->call_chain.next_node = NULL;
}

void vcpu_set_running(struct vcpu_locked target_locked,
		      const struct ffa_value *args);

void vcpu_save_interrupt_priority(struct vcpu_locked vcpu_locked,
				  uint8_t priority);

void vcpu_enter_secure_interrupt_rtm(struct vcpu_locked vcpu_locked);

void vcpu_secure_interrupt_complete(struct vcpu_locked vcpu_locked);

static inline bool vcpu_is_virt_interrupt_pending(struct interrupts *interrupts,
						  uint32_t intid)
{
	return interrupt_bitmap_get_value(&interrupts->interrupt_pending,
					  intid) == 1U;
}

static inline enum interrupt_type vcpu_virt_interrupt_get_type(
	struct interrupts *interrupts, uint32_t intid)
{
	return (enum interrupt_type)interrupt_bitmap_get_value(
		&interrupts->interrupt_type, intid);
}

static inline void vcpu_virt_interrupt_set_type(struct interrupts *interrupts,
						uint32_t intid,
						enum interrupt_type type)
{
	if (type == INTERRUPT_TYPE_IRQ) {
		interrupt_bitmap_clear_value(&interrupts->interrupt_type,
					     intid);
	} else {
		interrupt_bitmap_set_value(&interrupts->interrupt_type, intid);
	}
}

uint32_t vcpu_virt_interrupt_irq_count_get(struct vcpu_locked vcpu_locked);
uint32_t vcpu_virt_interrupt_fiq_count_get(struct vcpu_locked vcpu_locked);
uint32_t vcpu_virt_interrupt_count_get(struct vcpu_locked vcpu_locked);

void vcpu_virt_interrupt_enable(struct vcpu_locked vcpu_locked,
				uint32_t vint_id, bool enable);

uint32_t vcpu_virt_interrupt_peek_pending_and_enabled(
	struct vcpu_locked vcpu_locked);
uint32_t vcpu_virt_interrupt_get_pending_and_enabled(
	struct vcpu_locked vcpu_locked);
void vcpu_virt_interrupt_inject(struct vcpu_locked vcpu_locked,
				uint32_t vint_id);
void vcpu_virt_interrupt_clear(struct vcpu_locked vcpu_locked,
			       uint32_t vint_id);

void vcpu_dir_req_set_state(struct vcpu_locked target_locked, bool is_ffa_req2,
			    ffa_id_t sender_vm_id, struct ffa_value args);

void vcpu_dir_req_reset_state(struct vcpu_locked vcpu_locked);
