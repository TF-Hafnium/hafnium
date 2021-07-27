/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/api.h"

#include "hf/arch/cpu.h"
#include "hf/arch/ffa.h"
#include "hf/arch/mm.h"
#include "hf/arch/other_world.h"
#include "hf/arch/plat/ffa.h"
#include "hf/arch/timer.h"
#include "hf/arch/vm.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa_internal.h"
#include "hf/ffa_memory.h"
#include "hf/mm.h"
#include "hf/plat/console.h"
#include "hf/plat/interrupts.h"
#include "hf/spinlock.h"
#include "hf/static_assert.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

static_assert(sizeof(struct ffa_partition_info) == 8,
	      "Partition information descriptor size doesn't match the one in "
	      "the FF-A 1.0 EAC specification, Table 82.");

/*
 * To eliminate the risk of deadlocks, we define a partial order for the
 * acquisition of locks held concurrently by the same physical CPU. Our current
 * ordering requirements are as follows:
 *
 * vm::lock -> vcpu::lock -> mm_stage1_lock -> dlog sl
 *
 * Locks of the same kind require the lock of lowest address to be locked first,
 * see `sl_lock_both()`.
 */

static_assert(HF_MAILBOX_SIZE == PAGE_SIZE,
	      "Currently, a page is mapped for the send and receive buffers so "
	      "the maximum request is the size of a page.");

static_assert(MM_PPOOL_ENTRY_SIZE >= HF_MAILBOX_SIZE,
	      "The page pool entry size must be at least as big as the mailbox "
	      "size, so that memory region descriptors can be copied from the "
	      "mailbox for memory sharing.");

static struct mpool api_page_pool;

/**
 * Initialises the API page pool by taking ownership of the contents of the
 * given page pool.
 */
void api_init(struct mpool *ppool)
{
	mpool_init_from(&api_page_pool, ppool);
}

/**
 * Get target VM vCPU:
 * If VM is UP then return first vCPU.
 * If VM is MP then return vCPU whose index matches current CPU index.
 */
static struct vcpu *api_ffa_get_vm_vcpu(struct vm *vm, struct vcpu *current)
{
	ffa_vcpu_index_t current_cpu_index = cpu_index(current->cpu);
	struct vcpu *vcpu = NULL;

	if (vm->vcpu_count == 1) {
		vcpu = vm_get_vcpu(vm, 0);
	} else if (current_cpu_index < vm->vcpu_count) {
		vcpu = vm_get_vcpu(vm, current_cpu_index);
	}

	return vcpu;
}

/**
 * Switches the physical CPU back to the corresponding vCPU of the VM whose ID
 * is given as argument of the function.
 *
 * Called to change the context between SPs for direct messaging (when Hafnium
 * is SPMC), and on the context of the remaining 'api_switch_to_*' functions.
 *
 * This function works for partitions that are:
 * - UP migratable.
 * - MP with pinned Execution Contexts.
 */
static struct vcpu *api_switch_to_vm(struct vcpu *current,
				     struct ffa_value to_ret,
				     enum vcpu_state vcpu_state,
				     ffa_vm_id_t to_id)
{
	struct vm *to_vm = vm_find(to_id);
	struct vcpu *next = api_ffa_get_vm_vcpu(to_vm, current);

	CHECK(next != NULL);

	/* Set the return value for the target VM. */
	arch_regs_set_retval(&next->regs, to_ret);

	/* Set the current vCPU state. */
	sl_lock(&current->lock);
	current->state = vcpu_state;
	sl_unlock(&current->lock);

	return next;
}

/**
 * Switches the physical CPU back to the corresponding vCPU of the primary VM.
 *
 * This triggers the scheduling logic to run. Run in the context of secondary VM
 * to cause FFA_RUN to return and the primary VM to regain control of the CPU.
 */
static struct vcpu *api_switch_to_primary(struct vcpu *current,
					  struct ffa_value primary_ret,
					  enum vcpu_state secondary_state)
{
	/*
	 * If the secondary is blocked but has a timer running, sleep until the
	 * timer fires rather than indefinitely.
	 */
	switch (primary_ret.func) {
	case HF_FFA_RUN_WAIT_FOR_INTERRUPT:
	case FFA_MSG_WAIT_32: {
		if (arch_timer_enabled_current()) {
			uint64_t remaining_ns =
				arch_timer_remaining_ns_current();

			if (remaining_ns == 0) {
				/*
				 * Timer is pending, so the current vCPU should
				 * be run again right away.
				 */
				primary_ret.func = FFA_INTERRUPT_32;
				/*
				 * primary_ret.arg1 should already be set to the
				 * current VM ID and vCPU ID.
				 */
				primary_ret.arg2 = 0;
			} else {
				primary_ret.arg2 = remaining_ns;
			}
		} else {
			primary_ret.arg2 = FFA_SLEEP_INDEFINITE;
		}
		break;
	}

	default:
		/* Do nothing. */
		break;
	}

	return api_switch_to_vm(current, primary_ret, secondary_state,
				HF_PRIMARY_VM_ID);
}

/**
 * Choose next vCPU to run to be the counterpart vCPU in the other
 * world (run the normal world if currently running in the secure
 * world). Set current vCPU state to the given vcpu_state parameter.
 * Set FF-A return values to the target vCPU in the other world.
 *
 * Called in context of a direct message response from a secure
 * partition to a VM.
 */
struct vcpu *api_switch_to_other_world(struct vcpu *current,
				       struct ffa_value other_world_ret,
				       enum vcpu_state vcpu_state)
{
	return api_switch_to_vm(current, other_world_ret, vcpu_state,
				HF_OTHER_WORLD_ID);
}

/**
 * Checks whether the given `to` VM's mailbox is currently busy, and optionally
 * registers the `from` VM to be notified when it becomes available.
 */
static bool msg_receiver_busy(struct vm_locked to, struct vm *from, bool notify)
{
	if (to.vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	    to.vm->mailbox.recv == NULL) {
		/*
		 * Fail if the receiver isn't currently ready to receive data,
		 * setting up for notification if requested.
		 */
		if (notify) {
			struct wait_entry *entry =
				vm_get_wait_entry(from, to.vm->id);

			/* Append waiter only if it's not there yet. */
			if (list_empty(&entry->wait_links)) {
				list_append(&to.vm->mailbox.waiter_list,
					    &entry->wait_links);
			}
		}

		return true;
	}

	return false;
}

/**
 * Returns true if the given vCPU is executing in context of an
 * FFA_MSG_SEND_DIRECT_REQ invocation.
 */
static bool is_ffa_direct_msg_request_ongoing(struct vcpu_locked locked)
{
	return locked.vcpu->direct_request_origin_vm_id != HF_INVALID_VM_ID;
}

/**
 * Returns true if the VM owning the given vCPU is supporting managed exit and
 * the vCPU is currently processing a managed exit.
 */
static bool api_ffa_is_managed_exit_ongoing(struct vcpu_locked vcpu_locked)
{
	return (plat_ffa_vm_managed_exit_supported(vcpu_locked.vcpu->vm) &&
		vcpu_locked.vcpu->processing_managed_exit);
}

/**
 * Returns to the primary VM and signals that the vCPU still has work to do so.
 */
struct vcpu *api_preempt(struct vcpu *current)
{
	struct ffa_value ret = {
		.func = FFA_INTERRUPT_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	return api_switch_to_primary(current, ret, VCPU_STATE_READY);
}

/**
 * Puts the current vCPU in wait for interrupt mode, and returns to the primary
 * VM.
 */
struct vcpu *api_wait_for_interrupt(struct vcpu *current)
{
	struct ffa_value ret = {
		.func = HF_FFA_RUN_WAIT_FOR_INTERRUPT,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	return api_switch_to_primary(current, ret,
				     VCPU_STATE_BLOCKED_INTERRUPT);
}

/**
 * Puts the current vCPU in off mode, and returns to the primary VM.
 */
struct vcpu *api_vcpu_off(struct vcpu *current)
{
	struct ffa_value ret = {
		.func = HF_FFA_RUN_WAIT_FOR_INTERRUPT,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	/*
	 * Disable the timer, so the scheduler doesn't get told to call back
	 * based on it.
	 */
	arch_timer_disable_current();

	return api_switch_to_primary(current, ret, VCPU_STATE_OFF);
}

/**
 * Returns to the primary VM to allow this CPU to be used for other tasks as the
 * vCPU does not have work to do at this moment. The current vCPU is marked as
 * ready to be scheduled again.
 */
struct ffa_value api_yield(struct vcpu *current, struct vcpu **next)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vcpu_locked current_locked;
	bool is_direct_request_ongoing;

	if (current->vm->id == HF_PRIMARY_VM_ID) {
		/* NOOP on the primary as it makes the scheduling decisions. */
		return ret;
	}

	current_locked = vcpu_lock(current);
	is_direct_request_ongoing =
		is_ffa_direct_msg_request_ongoing(current_locked);
	vcpu_unlock(&current_locked);

	if (is_direct_request_ongoing) {
		return ffa_error(FFA_DENIED);
	}

	*next = api_switch_to_primary(
		current,
		(struct ffa_value){.func = FFA_YIELD_32,
				   .arg1 = ffa_vm_vcpu(current->vm->id,
						       vcpu_index(current))},
		VCPU_STATE_READY);

	return ret;
}

/**
 * Switches to the primary so that it can switch to the target, or kick it if it
 * is already running on a different physical CPU.
 */
struct vcpu *api_wake_up(struct vcpu *current, struct vcpu *target_vcpu)
{
	struct ffa_value ret = {
		.func = HF_FFA_RUN_WAKE_UP,
		.arg1 = ffa_vm_vcpu(target_vcpu->vm->id,
				    vcpu_index(target_vcpu)),
	};
	return api_switch_to_primary(current, ret, VCPU_STATE_READY);
}

/**
 * Aborts the vCPU and triggers its VM to abort fully.
 */
struct vcpu *api_abort(struct vcpu *current)
{
	struct ffa_value ret = ffa_error(FFA_ABORTED);

	dlog_notice("Aborting VM %#x vCPU %u\n", current->vm->id,
		    vcpu_index(current));

	if (current->vm->id == HF_PRIMARY_VM_ID) {
		/* TODO: what to do when the primary aborts? */
		for (;;) {
			/* Do nothing. */
		}
	}

	atomic_store_explicit(&current->vm->aborting, true,
			      memory_order_relaxed);

	/* TODO: free resources once all vCPUs abort. */

	return api_switch_to_primary(current, ret, VCPU_STATE_ABORTED);
}

struct ffa_value api_ffa_partition_info_get(struct vcpu *current,
					    const struct ffa_uuid *uuid)
{
	struct vm *current_vm = current->vm;
	struct vm_locked current_vm_locked;
	ffa_vm_count_t vm_count = 0;
	bool uuid_is_null = ffa_uuid_is_null(uuid);
	struct ffa_value ret;
	uint32_t size;
	struct ffa_partition_info partitions[MAX_VMS];

	/*
	 * Iterate through the VMs to find the ones with a matching UUID.
	 * A Null UUID retrieves information for all VMs.
	 */
	for (uint16_t index = 0; index < vm_get_count(); ++index) {
		const struct vm *vm = vm_find_index(index);

		if (uuid_is_null || ffa_uuid_equal(uuid, &vm->uuid)) {
			partitions[vm_count].vm_id = vm->id;
			partitions[vm_count].vcpu_count = vm->vcpu_count;
			partitions[vm_count].properties =
				plat_ffa_partition_properties(current_vm->id,
							      vm);

			++vm_count;
		}
	}

	/* Unrecognized UUID: does not match any of the VMs and is not Null. */
	if (vm_count == 0) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	size = vm_count * sizeof(partitions[0]);
	if (size > FFA_MSG_PAYLOAD_MAX) {
		dlog_error(
			"Partition information does not fit in the VM's RX "
			"buffer.\n");
		return ffa_error(FFA_NO_MEMORY);
	}

	/*
	 * Partition information is returned in the VM's RX buffer, which is why
	 * the lock is needed.
	 */
	current_vm_locked = vm_lock(current_vm);

	if (msg_receiver_busy(current_vm_locked, NULL, false)) {
		/*
		 * Can't retrieve memory information if the mailbox is not
		 * available.
		 */
		dlog_verbose("RX buffer not ready.\n");
		ret = ffa_error(FFA_BUSY);
		goto out_unlock;
	}

	/* Populate the VM's RX buffer with the partition information. */
	memcpy_s(current_vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX, partitions,
		 size);
	current_vm->mailbox.recv_size = size;
	current_vm->mailbox.recv_sender = HF_HYPERVISOR_VM_ID;
	current_vm->mailbox.recv_func = FFA_PARTITION_INFO_GET_32;
	current_vm->mailbox.state = MAILBOX_STATE_READ;

	/* Return the count of partition information descriptors in w2. */
	ret = (struct ffa_value){.func = FFA_SUCCESS_32, .arg2 = vm_count};

out_unlock:
	vm_unlock(&current_vm_locked);

	return ret;
}

/**
 * Returns the ID of the VM.
 */
struct ffa_value api_ffa_id_get(const struct vcpu *current)
{
	return (struct ffa_value){.func = FFA_SUCCESS_32,
				  .arg2 = current->vm->id};
}

/**
 * Returns the ID of the SPMC.
 */
struct ffa_value api_ffa_spm_id_get(void)
{
#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
	/*
	 * Return the SPMC ID that was fetched during FF-A
	 * initialization.
	 */
	return (struct ffa_value){.func = FFA_SUCCESS_32,
				  .arg2 = arch_ffa_spmc_id_get()};
#else
	return ffa_error(FFA_NOT_SUPPORTED);
#endif
}

/**
 * This function is called by the architecture-specific context switching
 * function to indicate that register state for the given vCPU has been saved
 * and can therefore be used by other pCPUs.
 */
void api_regs_state_saved(struct vcpu *vcpu)
{
	sl_lock(&vcpu->lock);
	vcpu->regs_available = true;
	sl_unlock(&vcpu->lock);
}

/**
 * Retrieves the next waiter and removes it from the wait list if the VM's
 * mailbox is in a writable state.
 */
static struct wait_entry *api_fetch_waiter(struct vm_locked locked_vm)
{
	struct wait_entry *entry;
	struct vm *vm = locked_vm.vm;

	if (vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	    vm->mailbox.recv == NULL || list_empty(&vm->mailbox.waiter_list)) {
		/* The mailbox is not writable or there are no waiters. */
		return NULL;
	}

	/* Remove waiter from the wait list. */
	entry = CONTAINER_OF(vm->mailbox.waiter_list.next, struct wait_entry,
			     wait_links);
	list_remove(&entry->wait_links);
	return entry;
}

/**
 * Assuming that the arguments have already been checked by the caller, injects
 * a virtual interrupt of the given ID into the given target vCPU. This doesn't
 * cause the vCPU to actually be run immediately; it will be taken when the vCPU
 * is next run, which is up to the scheduler.
 *
 * Returns:
 *  - 0 on success if no further action is needed.
 *  - 1 if it was called by the primary VM and the primary VM now needs to wake
 *    up or kick the target vCPU.
 */
int64_t api_interrupt_inject_locked(struct vcpu_locked target_locked,
				    uint32_t intid, struct vcpu *current,
				    struct vcpu **next)
{
	struct vcpu *target_vcpu = target_locked.vcpu;
	uint32_t intid_index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t intid_shift = intid % INTERRUPT_REGISTER_BITS;
	uint32_t intid_mask = 1U << intid_shift;
	int64_t ret = 0;

	/*
	 * We only need to change state and (maybe) trigger a virtual interrupt
	 * if it is enabled and was not previously pending. Otherwise we can
	 * skip everything except setting the pending bit.
	 */
	if (!(target_vcpu->interrupts.interrupt_enabled[intid_index] &
	      ~target_vcpu->interrupts.interrupt_pending[intid_index] &
	      intid_mask)) {
		goto out;
	}

	/* Increment the count. */
	if ((target_vcpu->interrupts.interrupt_type[intid_index] &
	     intid_mask) == (INTERRUPT_TYPE_IRQ << intid_shift)) {
		vcpu_irq_count_increment(target_locked);
	} else {
		vcpu_fiq_count_increment(target_locked);
	}

	/*
	 * Only need to update state if there was not already an
	 * interrupt enabled and pending.
	 */
	if (vcpu_interrupt_count_get(target_locked) != 1) {
		goto out;
	}

	if (current->vm->id == HF_PRIMARY_VM_ID) {
		/*
		 * If the call came from the primary VM, let it know that it
		 * should run or kick the target vCPU.
		 */
		ret = 1;
	} else if (current != target_vcpu && next != NULL) {
		*next = api_wake_up(current, target_vcpu);
	}

out:
	/* Either way, make it pending. */
	target_vcpu->interrupts.interrupt_pending[intid_index] |= intid_mask;

	return ret;
}

/* Wrapper to internal_interrupt_inject with locking of target vCPU */
static int64_t internal_interrupt_inject(struct vcpu *target_vcpu,
					 uint32_t intid, struct vcpu *current,
					 struct vcpu **next)
{
	int64_t ret;
	struct vcpu_locked target_locked;

	target_locked = vcpu_lock(target_vcpu);
	ret = api_interrupt_inject_locked(target_locked, intid, current, next);
	vcpu_unlock(&target_locked);

	return ret;
}

/**
 * Constructs an FFA_MSG_SEND value to return from a successful FFA_MSG_POLL
 * or FFA_MSG_WAIT call.
 */
static struct ffa_value ffa_msg_recv_return(const struct vm *receiver)
{
	switch (receiver->mailbox.recv_func) {
	case FFA_MSG_SEND_32:
		return (struct ffa_value){
			.func = FFA_MSG_SEND_32,
			.arg1 = (receiver->mailbox.recv_sender << 16) |
				receiver->id,
			.arg3 = receiver->mailbox.recv_size};
	default:
		/* This should never be reached, but return an error in case. */
		dlog_error("Tried to return an invalid message function %#x\n",
			   receiver->mailbox.recv_func);
		return ffa_error(FFA_DENIED);
	}
}

/**
 * Prepares the vCPU to run by updating its state and fetching whether a return
 * value needs to be forced onto the vCPU.
 */
static bool api_vcpu_prepare_run(const struct vcpu *current, struct vcpu *vcpu,
				 struct ffa_value *run_ret)
{
	struct vcpu_locked vcpu_locked;
	struct vm_locked vm_locked;
	bool need_vm_lock;
	bool ret;

	/*
	 * Check that the registers are available so that the vCPU can be run.
	 *
	 * The VM lock is not needed in the common case so it must only be taken
	 * when it is going to be needed. This ensures there are no inter-vCPU
	 * dependencies in the common run case meaning the sensitive context
	 * switch performance is consistent.
	 */
	vcpu_locked = vcpu_lock(vcpu);

#if SECURE_WORLD == 1

	if (vcpu_secondary_reset_and_start(vcpu_locked, vcpu->vm->secondary_ep,
					   0)) {
		dlog_verbose("%s secondary cold boot vmid %#x vcpu id %#x\n",
			     __func__, vcpu->vm->id, current->cpu->id);
	}

#endif

	/* The VM needs to be locked to deliver mailbox messages. */
	need_vm_lock = vcpu->state == VCPU_STATE_BLOCKED_MAILBOX;
	if (need_vm_lock) {
		vcpu_unlock(&vcpu_locked);
		vm_locked = vm_lock(vcpu->vm);
		vcpu_locked = vcpu_lock(vcpu);
	}

	/*
	 * If the vCPU is already running somewhere then we can't run it here
	 * simultaneously. While it is actually running then the state should be
	 * `VCPU_STATE_RUNNING` and `regs_available` should be false. Once it
	 * stops running but while Hafnium is in the process of switching back
	 * to the primary there will be a brief period while the state has been
	 * updated but `regs_available` is still false (until
	 * `api_regs_state_saved` is called). We can't start running it again
	 * until this has finished, so count this state as still running for the
	 * purposes of this check.
	 */
	if (vcpu->state == VCPU_STATE_RUNNING || !vcpu->regs_available) {
		/*
		 * vCPU is running on another pCPU.
		 *
		 * It's okay not to return the sleep duration here because the
		 * other physical CPU that is currently running this vCPU will
		 * return the sleep duration if needed.
		 */
		*run_ret = ffa_error(FFA_BUSY);
		ret = false;
		goto out;
	}

	if (atomic_load_explicit(&vcpu->vm->aborting, memory_order_relaxed)) {
		if (vcpu->state != VCPU_STATE_ABORTED) {
			dlog_notice("Aborting VM %#x vCPU %u\n", vcpu->vm->id,
				    vcpu_index(vcpu));
			vcpu->state = VCPU_STATE_ABORTED;
		}
		ret = false;
		goto out;
	}

	switch (vcpu->state) {
	case VCPU_STATE_RUNNING:
	case VCPU_STATE_OFF:
	case VCPU_STATE_ABORTED:
		ret = false;
		goto out;

	case VCPU_STATE_BLOCKED_MAILBOX:
		/*
		 * A pending message allows the vCPU to run so the message can
		 * be delivered directly.
		 */
		if (vcpu->vm->mailbox.state == MAILBOX_STATE_RECEIVED) {
			arch_regs_set_retval(&vcpu->regs,
					     ffa_msg_recv_return(vcpu->vm));
			vcpu->vm->mailbox.state = MAILBOX_STATE_READ;
			break;
		}
		/* Fall through. */
	case VCPU_STATE_BLOCKED_INTERRUPT:
		/* Allow virtual interrupts to be delivered. */
		if (vcpu_interrupt_count_get(vcpu_locked) > 0) {
			break;
		}

		uint64_t timer_remaining_ns = FFA_SLEEP_INDEFINITE;

		if (arch_timer_enabled(&vcpu->regs)) {
			timer_remaining_ns =
				arch_timer_remaining_ns(&vcpu->regs);

			/*
			 * The timer expired so allow the interrupt to be
			 * delivered.
			 */
			if (timer_remaining_ns == 0) {
				break;
			}
		}

		/*
		 * The vCPU is not ready to run, return the appropriate code to
		 * the primary which called vcpu_run.
		 */
		run_ret->func = vcpu->state == VCPU_STATE_BLOCKED_MAILBOX
					? FFA_MSG_WAIT_32
					: HF_FFA_RUN_WAIT_FOR_INTERRUPT;
		run_ret->arg1 = ffa_vm_vcpu(vcpu->vm->id, vcpu_index(vcpu));
		run_ret->arg2 = timer_remaining_ns;

		ret = false;
		goto out;

	case VCPU_STATE_READY:
		break;
	}

	/* It has been decided that the vCPU should be run. */
	vcpu->cpu = current->cpu;
	vcpu->state = VCPU_STATE_RUNNING;

	/*
	 * Mark the registers as unavailable now that we're about to reflect
	 * them onto the real registers. This will also prevent another physical
	 * CPU from trying to read these registers.
	 */
	vcpu->regs_available = false;

	ret = true;

out:
	vcpu_unlock(&vcpu_locked);
	if (need_vm_lock) {
		vm_unlock(&vm_locked);
	}

	return ret;
}

struct ffa_value api_ffa_run(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			     const struct vcpu *current, struct vcpu **next)
{
	struct vm *vm;
	struct vcpu *vcpu;
	struct ffa_value ret = ffa_error(FFA_INVALID_PARAMETERS);

	/* Only the primary VM can switch vCPUs. */
	if (current->vm->id != HF_PRIMARY_VM_ID) {
		ret.arg2 = FFA_DENIED;
		goto out;
	}

	/* Only secondary VM vCPUs can be run. */
	if (vm_id == HF_PRIMARY_VM_ID) {
		goto out;
	}

	if (plat_ffa_run_forward(vm_id, vcpu_idx, &ret)) {
		return ret;
	}

	/* The requested VM must exist. */
	vm = vm_find(vm_id);
	if (vm == NULL) {
		goto out;
	}

	/* The requested vCPU must exist. */
	if (vcpu_idx >= vm->vcpu_count) {
		goto out;
	}

	/* Update state if allowed. */
	vcpu = vm_get_vcpu(vm, vcpu_idx);
	if (!api_vcpu_prepare_run(current, vcpu, &ret)) {
		goto out;
	}

	/*
	 * Inject timer interrupt if timer has expired. It's safe to access
	 * vcpu->regs here because api_vcpu_prepare_run already made sure that
	 * regs_available was true (and then set it to false) before returning
	 * true.
	 */
	if (arch_timer_pending(&vcpu->regs)) {
		/* Make virtual timer interrupt pending. */
		internal_interrupt_inject(vcpu, HF_VIRTUAL_TIMER_INTID, vcpu,
					  NULL);

		/*
		 * Set the mask bit so the hardware interrupt doesn't fire
		 * again. Ideally we wouldn't do this because it affects what
		 * the secondary vCPU sees, but if we don't then we end up with
		 * a loop of the interrupt firing each time we try to return to
		 * the secondary vCPU.
		 */
		arch_timer_mask(&vcpu->regs);
	}

	/* Switch to the vCPU. */
	*next = vcpu;

	/*
	 * Set a placeholder return code to the scheduler. This will be
	 * overwritten when the switch back to the primary occurs.
	 */
	ret.func = FFA_INTERRUPT_32;
	ret.arg1 = ffa_vm_vcpu(vm_id, vcpu_idx);
	ret.arg2 = 0;

out:
	return ret;
}

/**
 * Check that the mode indicates memory that is valid, owned and exclusive.
 */
static bool api_mode_valid_owned_and_exclusive(uint32_t mode)
{
	return (mode & (MM_MODE_D | MM_MODE_INVALID | MM_MODE_UNOWNED |
			MM_MODE_SHARED)) == 0;
}

/**
 * Determines the value to be returned by api_ffa_rxtx_map and
 * api_ffa_rx_release after they've succeeded. If a secondary VM is running and
 * there are waiters, it also switches back to the primary VM for it to wake
 * waiters up.
 */
static struct ffa_value api_waiter_result(struct vm_locked locked_vm,
					  struct vcpu *current,
					  struct vcpu **next)
{
	struct vm *vm = locked_vm.vm;

	if (list_empty(&vm->mailbox.waiter_list)) {
		/* No waiters, nothing else to do. */
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	}

	if (vm->id == HF_PRIMARY_VM_ID) {
		/* The caller is the primary VM. Tell it to wake up waiters. */
		return (struct ffa_value){.func = FFA_RX_RELEASE_32};
	}

	/*
	 * Switch back to the primary VM, informing it that there are waiters
	 * that need to be notified.
	 */
	*next = api_switch_to_primary(
		current, (struct ffa_value){.func = FFA_RX_RELEASE_32},
		VCPU_STATE_READY);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Configures the hypervisor's stage-1 view of the send and receive pages.
 */
static bool api_vm_configure_stage1(struct mm_stage1_locked mm_stage1_locked,
				    struct vm_locked vm_locked,
				    paddr_t pa_send_begin, paddr_t pa_send_end,
				    paddr_t pa_recv_begin, paddr_t pa_recv_end,
				    uint32_t extra_attributes,
				    struct mpool *local_page_pool)
{
	bool ret;

	/* Map the send page as read-only in the hypervisor address space. */
	vm_locked.vm->mailbox.send =
		mm_identity_map(mm_stage1_locked, pa_send_begin, pa_send_end,
				MM_MODE_R | extra_attributes, local_page_pool);
	if (!vm_locked.vm->mailbox.send) {
		/* TODO: partial defrag of failed range. */
		/* Recover any memory consumed in failed mapping. */
		mm_defrag(mm_stage1_locked, local_page_pool);
		goto fail;
	}

	/*
	 * Map the receive page as writable in the hypervisor address space. On
	 * failure, unmap the send page before returning.
	 */
	vm_locked.vm->mailbox.recv =
		mm_identity_map(mm_stage1_locked, pa_recv_begin, pa_recv_end,
				MM_MODE_W | extra_attributes, local_page_pool);
	if (!vm_locked.vm->mailbox.recv) {
		/* TODO: partial defrag of failed range. */
		/* Recover any memory consumed in failed mapping. */
		mm_defrag(mm_stage1_locked, local_page_pool);
		goto fail_undo_send;
	}

	ret = true;
	goto out;

	/*
	 * The following mappings will not require more memory than is available
	 * in the local pool.
	 */
fail_undo_send:
	vm_locked.vm->mailbox.send = NULL;
	CHECK(mm_unmap(mm_stage1_locked, pa_send_begin, pa_send_end,
		       local_page_pool));

fail:
	ret = false;

out:
	return ret;
}

/**
 * Sanity checks and configures the send and receive pages in the VM stage-2
 * and hypervisor stage-1 page tables.
 *
 * Returns:
 *  - FFA_ERROR FFA_INVALID_PARAMETERS if the given addresses are not properly
 *    aligned, are the same or have invalid attributes.
 *  - FFA_ERROR FFA_NO_MEMORY if the hypervisor was unable to map the buffers
 *    due to insuffient page table memory.
 *  - FFA_ERROR FFA_DENIED if the pages are already mapped.
 *  - FFA_SUCCESS on success if no further action is needed.
 */

struct ffa_value api_vm_configure_pages(
	struct mm_stage1_locked mm_stage1_locked, struct vm_locked vm_locked,
	ipaddr_t send, ipaddr_t recv, uint32_t page_count,
	struct mpool *local_page_pool)
{
	struct ffa_value ret;
	paddr_t pa_send_begin;
	paddr_t pa_send_end;
	paddr_t pa_recv_begin;
	paddr_t pa_recv_end;
	uint32_t orig_send_mode;
	uint32_t orig_recv_mode;
	uint32_t extra_attributes;

	/* We only allow these to be setup once. */
	if (vm_locked.vm->mailbox.send || vm_locked.vm->mailbox.recv) {
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/* Hafnium only supports a fixed size of RX/TX buffers. */
	if (page_count != HF_MAILBOX_SIZE / FFA_PAGE_SIZE) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Fail if addresses are not page-aligned. */
	if (!is_aligned(ipa_addr(send), PAGE_SIZE) ||
	    !is_aligned(ipa_addr(recv), PAGE_SIZE)) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Convert to physical addresses. */
	pa_send_begin = pa_from_ipa(send);
	pa_send_end = pa_add(pa_send_begin, HF_MAILBOX_SIZE);
	pa_recv_begin = pa_from_ipa(recv);
	pa_recv_end = pa_add(pa_recv_begin, HF_MAILBOX_SIZE);

	/* Fail if the same page is used for the send and receive pages. */
	if (pa_addr(pa_send_begin) == pa_addr(pa_recv_begin)) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Ensure the pages are valid, owned and exclusive to the VM and that
	 * the VM has the required access to the memory.
	 */
	if (!vm_mem_get_mode(vm_locked, send, ipa_add(send, PAGE_SIZE),
			     &orig_send_mode) ||
	    !api_mode_valid_owned_and_exclusive(orig_send_mode) ||
	    (orig_send_mode & MM_MODE_R) == 0 ||
	    (orig_send_mode & MM_MODE_W) == 0) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!vm_mem_get_mode(vm_locked, recv, ipa_add(recv, PAGE_SIZE),
			     &orig_recv_mode) ||
	    !api_mode_valid_owned_and_exclusive(orig_recv_mode) ||
	    (orig_recv_mode & MM_MODE_R) == 0) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Take memory ownership away from the VM and mark as shared. */
	uint32_t mode =
		MM_MODE_UNOWNED | MM_MODE_SHARED | MM_MODE_R | MM_MODE_W;
	if (vm_locked.vm->el0_partition) {
		mode |= MM_MODE_USER | MM_MODE_NG;
	}

	if (!vm_identity_map(vm_locked, pa_send_begin, pa_send_end, mode,
			     local_page_pool, NULL)) {
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	mode = MM_MODE_UNOWNED | MM_MODE_SHARED | MM_MODE_R;
	if (vm_locked.vm->el0_partition) {
		mode |= MM_MODE_USER | MM_MODE_NG;
	}

	if (!vm_identity_map(vm_locked, pa_recv_begin, pa_recv_end, mode,
			     local_page_pool, NULL)) {
		/* TODO: partial defrag of failed range. */
		/* Recover any memory consumed in failed mapping. */
		mm_vm_defrag(&vm_locked.vm->ptable, local_page_pool);
		goto fail_undo_send;
	}

	/* Get extra send/recv pages mapping attributes for the given VM ID. */
	extra_attributes = arch_mm_extra_attributes_from_vm(vm_locked.vm->id);

	/*
	 * For EL0 partitions, since both the partition and the hypervisor code
	 * use the EL2&0 translation regime, it is critical to mark the mappings
	 * of the send and recv buffers as non-global in the TLB. For one, if we
	 * dont mark it as non-global, it would cause TLB conflicts since there
	 * would be an identity mapping with non-global attribute in the
	 * partitions page tables, but another identity mapping in the
	 * hypervisor page tables with the global attribute. The other issue is
	 * one of security, we dont want other partitions to be able to access
	 * other partitions buffers through cached translations.
	 */
	if (vm_locked.vm->el0_partition) {
		extra_attributes |= MM_MODE_NG;
	}

	if (!api_vm_configure_stage1(mm_stage1_locked, vm_locked, pa_send_begin,
				     pa_send_end, pa_recv_begin, pa_recv_end,
				     extra_attributes, local_page_pool)) {
		goto fail_undo_send_and_recv;
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	goto out;

fail_undo_send_and_recv:
	CHECK(vm_identity_map(vm_locked, pa_recv_begin, pa_recv_end,
			      orig_send_mode, local_page_pool, NULL));

fail_undo_send:
	CHECK(vm_identity_map(vm_locked, pa_send_begin, pa_send_end,
			      orig_send_mode, local_page_pool, NULL));
	ret = ffa_error(FFA_NO_MEMORY);

out:
	return ret;
}

/**
 * Configures the VM to send/receive data through the specified pages. The pages
 * must not be shared. Locking of the page tables combined with a local memory
 * pool ensures there will always be enough memory to recover from any errors
 * that arise. The stage-1 page tables must be locked so memory cannot be taken
 * by another core which could result in this transaction being unable to roll
 * back in the case of an error.
 *
 * Returns:
 *  - FFA_ERROR FFA_INVALID_PARAMETERS if the given addresses are not properly
 *    aligned, are the same or have invalid attributes.
 *  - FFA_ERROR FFA_NO_MEMORY if the hypervisor was unable to map the buffers
 *    due to insuffient page table memory.
 *  - FFA_ERROR FFA_DENIED if the pages are already mapped.
 *  - FFA_SUCCESS on success if no further action is needed.
 *  - FFA_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters.
 */
struct ffa_value api_ffa_rxtx_map(ipaddr_t send, ipaddr_t recv,
				  uint32_t page_count, struct vcpu *current,
				  struct vcpu **next)
{
	struct vm *vm = current->vm;
	struct ffa_value ret;
	struct vm_locked vm_locked;
	struct mm_stage1_locked mm_stage1_locked;
	struct mpool local_page_pool;

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if any
	 * stage of the process fails.
	 */
	mpool_init_with_fallback(&local_page_pool, &api_page_pool);

	vm_locked = vm_lock(vm);
	mm_stage1_locked = mm_lock_stage1();

	ret = api_vm_configure_pages(mm_stage1_locked, vm_locked, send, recv,
				     page_count, &local_page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto exit;
	}

	/* Tell caller about waiters, if any. */
	ret = api_waiter_result(vm_locked, current, next);

exit:
	mpool_fini(&local_page_pool);

	mm_unlock_stage1(&mm_stage1_locked);
	vm_unlock(&vm_locked);

	return ret;
}

/**
 * Unmaps the RX/TX buffer pair with a partition or partition manager from the
 * translation regime of the caller. Unmap the region for the hypervisor and
 * set the memory region to owned and exclusive for the component. Since the
 * memory region mapped in the page table, when the buffers were originally
 * created we can safely remap it.
 *
 * Returns:
 *   - FFA_ERROR FFA_INVALID_PARAMETERS if there is no buffer pair registered on
 *     behalf of the caller.
 *   - FFA_SUCCESS on success if no further action is needed.
 */
struct ffa_value api_ffa_rxtx_unmap(ffa_vm_id_t allocator_id,
				    struct vcpu *current)
{
	struct vm *vm = current->vm;
	struct vm_locked vm_locked;
	struct mm_stage1_locked mm_stage1_locked;
	paddr_t send_pa_begin;
	paddr_t send_pa_end;
	paddr_t recv_pa_begin;
	paddr_t recv_pa_end;

	/*
	 * Check there is a buffer pair registered on behalf of the caller.
	 * Since forwarding is not yet supported the allocator ID MBZ.
	 */
	if (allocator_id != 0) {
		dlog_error(
			"Forwarding MAP/UNMAP from the hypervisor is not yet "
			"supported so vm id must be zero.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Get send and receive buffers. */
	if (vm->mailbox.send == NULL || vm->mailbox.recv == NULL) {
		dlog_error(
			"No buffer pair registered on behalf of the caller.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Currently a mailbox size of 1 page is assumed. */
	send_pa_begin = pa_from_va(va_from_ptr(vm->mailbox.send));
	send_pa_end = pa_add(send_pa_begin, HF_MAILBOX_SIZE);
	recv_pa_begin = pa_from_va(va_from_ptr(vm->mailbox.recv));
	recv_pa_end = pa_add(recv_pa_begin, HF_MAILBOX_SIZE);

	vm_locked = vm_lock(vm);
	mm_stage1_locked = mm_lock_stage1();

	/*
	 * Set the memory region of the buffers back to the default mode
	 * for the VM. Since this memory region was already mapped for the
	 * RXTX buffers we can safely remap them.
	 */
	CHECK(vm_identity_map(vm_locked, send_pa_begin, send_pa_end,
			      MM_MODE_R | MM_MODE_W | MM_MODE_X, &api_page_pool,
			      NULL));

	CHECK(vm_identity_map(vm_locked, recv_pa_begin, recv_pa_end,
			      MM_MODE_R | MM_MODE_W | MM_MODE_X, &api_page_pool,
			      NULL));

	/* Unmap the buffers in the partition manager. */
	CHECK(mm_unmap(mm_stage1_locked, send_pa_begin, send_pa_end,
		       &api_page_pool));
	CHECK(mm_unmap(mm_stage1_locked, recv_pa_begin, recv_pa_end,
		       &api_page_pool));

	vm->mailbox.send = NULL;
	vm->mailbox.recv = NULL;

	mm_unlock_stage1(&mm_stage1_locked);
	vm_unlock(&vm_locked);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

/**
 * Notifies the `to` VM about the message currently in its mailbox, possibly
 * with the help of the primary VM.
 */
static struct ffa_value deliver_msg(struct vm_locked to, ffa_vm_id_t from_id,
				    struct vcpu *current, struct vcpu **next)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct ffa_value primary_ret = {
		.func = FFA_MSG_SEND_32,
		.arg1 = ((uint32_t)from_id << 16) | to.vm->id,
	};

	/* Messages for the primary VM are delivered directly. */
	if (to.vm->id == HF_PRIMARY_VM_ID) {
		/*
		 * Only tell the primary VM the size and other details if the
		 * message is for it, to avoid leaking data about messages for
		 * other VMs.
		 */
		primary_ret = ffa_msg_recv_return(to.vm);

		to.vm->mailbox.state = MAILBOX_STATE_READ;
		*next = api_switch_to_primary(current, primary_ret,
					      VCPU_STATE_READY);
		return ret;
	}

	to.vm->mailbox.state = MAILBOX_STATE_RECEIVED;

	/* Messages for the TEE are sent on via the dispatcher. */
	if (to.vm->id == HF_TEE_VM_ID) {
		struct ffa_value call = ffa_msg_recv_return(to.vm);

		ret = arch_other_world_call(call);
		/*
		 * After the call to the TEE completes it must have finished
		 * reading its RX buffer, so it is ready for another message.
		 */
		to.vm->mailbox.state = MAILBOX_STATE_EMPTY;
		/*
		 * Don't return to the primary VM in this case, as the TEE is
		 * not (yet) scheduled via FF-A.
		 */
		return ret;
	}

	/* Return to the primary VM directly or with a switch. */
	if (from_id != HF_PRIMARY_VM_ID) {
		*next = api_switch_to_primary(current, primary_ret,
					      VCPU_STATE_READY);
	}

	return ret;
}

/**
 * Copies data from the sender's send buffer to the recipient's receive buffer
 * and notifies the recipient.
 *
 * If the recipient's receive buffer is busy, it can optionally register the
 * caller to be notified when the recipient's receive buffer becomes available.
 */
struct ffa_value api_ffa_msg_send(ffa_vm_id_t sender_vm_id,
				  ffa_vm_id_t receiver_vm_id, uint32_t size,
				  uint32_t attributes, struct vcpu *current,
				  struct vcpu **next)
{
	struct vm *from = current->vm;
	struct vm *to;
	struct vm_locked to_locked;
	const void *from_msg;
	struct ffa_value ret;
	struct vcpu_locked current_locked;
	bool is_direct_request_ongoing;
	bool notify =
		(attributes & FFA_MSG_SEND_NOTIFY_MASK) == FFA_MSG_SEND_NOTIFY;

	/* Ensure sender VM ID corresponds to the current VM. */
	if (sender_vm_id != from->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Disallow reflexive requests as this suggests an error in the VM. */
	if (receiver_vm_id == from->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Limit the size of transfer. */
	if (size > FFA_MSG_PAYLOAD_MAX) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Deny if vCPU is executing in context of an FFA_MSG_SEND_DIRECT_REQ
	 * invocation.
	 */
	current_locked = vcpu_lock(current);
	is_direct_request_ongoing =
		is_ffa_direct_msg_request_ongoing(current_locked);
	vcpu_unlock(&current_locked);

	if (is_direct_request_ongoing) {
		return ffa_error(FFA_DENIED);
	}

	/* Ensure the receiver VM exists. */
	to = vm_find(receiver_vm_id);
	if (to == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check that the sender has configured its send buffer. If the tx
	 * mailbox at from_msg is configured (i.e. from_msg != NULL) then it can
	 * be safely accessed after releasing the lock since the tx mailbox
	 * address can only be configured once.
	 */
	sl_lock(&from->lock);
	from_msg = from->mailbox.send;
	sl_unlock(&from->lock);

	if (from_msg == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	to_locked = vm_lock(to);

	if (msg_receiver_busy(to_locked, from, notify)) {
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	/* Copy data. */
	memcpy_s(to->mailbox.recv, FFA_MSG_PAYLOAD_MAX, from_msg, size);
	to->mailbox.recv_size = size;
	to->mailbox.recv_sender = sender_vm_id;
	to->mailbox.recv_func = FFA_MSG_SEND_32;
	ret = deliver_msg(to_locked, sender_vm_id, current, next);

out:
	vm_unlock(&to_locked);

	return ret;
}

/**
 * Checks whether the vCPU's attempt to block for a message has already been
 * interrupted or whether it is allowed to block.
 */
bool api_ffa_msg_recv_block_interrupted(struct vcpu *current)
{
	struct vcpu_locked current_locked;
	bool interrupted;

	current_locked = vcpu_lock(current);

	/*
	 * Don't block if there are enabled and pending interrupts, to match
	 * behaviour of wait_for_interrupt.
	 */
	interrupted = (vcpu_interrupt_count_get(current_locked) > 0);

	vcpu_unlock(&current_locked);

	return interrupted;
}

/**
 * Receives a message from the mailbox. If one isn't available, this function
 * can optionally block the caller until one becomes available.
 *
 * No new messages can be received until the mailbox has been cleared.
 */
struct ffa_value api_ffa_msg_recv(bool block, struct vcpu *current,
				  struct vcpu **next)
{
	bool is_direct_request_ongoing;
	struct vcpu_locked current_locked;
	struct vm *vm = current->vm;
	struct ffa_value return_code;
	bool is_from_secure_world =
		(current->vm->id & HF_VM_ID_WORLD_MASK) != 0;

	/*
	 * The primary VM will receive messages as a status code from running
	 * vCPUs and must not call this function.
	 */
	if (!is_from_secure_world && vm->id == HF_PRIMARY_VM_ID) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	/*
	 * Deny if vCPU is executing in context of an FFA_MSG_SEND_DIRECT_REQ
	 * invocation.
	 */
	current_locked = vcpu_lock(current);
	is_direct_request_ongoing =
		is_ffa_direct_msg_request_ongoing(current_locked);
	vcpu_unlock(&current_locked);

	if (is_direct_request_ongoing) {
		return ffa_error(FFA_DENIED);
	}

	sl_lock(&vm->lock);

	/* Return pending messages without blocking. */
	if (vm->mailbox.state == MAILBOX_STATE_RECEIVED) {
		vm->mailbox.state = MAILBOX_STATE_READ;
		return_code = ffa_msg_recv_return(vm);
		goto out;
	}

	/* No pending message so fail if not allowed to block. */
	if (!block) {
		return_code = ffa_error(FFA_RETRY);
		goto out;
	}

	/*
	 * From this point onward this call can only be interrupted or a message
	 * received. If a message is received the return value will be set at
	 * that time to FFA_SUCCESS.
	 */
	return_code = ffa_error(FFA_INTERRUPTED);
	if (api_ffa_msg_recv_block_interrupted(current)) {
		goto out;
	}

	if (is_from_secure_world) {
		/* Return to other world if caller is a SP. */
		*next = api_switch_to_other_world(
			current, (struct ffa_value){.func = FFA_MSG_WAIT_32},
			VCPU_STATE_BLOCKED_MAILBOX);
	} else {
		/* Switch back to primary VM to block. */
		struct ffa_value run_return = {
			.func = FFA_MSG_WAIT_32,
			.arg1 = ffa_vm_vcpu(vm->id, vcpu_index(current)),
		};

		*next = api_switch_to_primary(current, run_return,
					      VCPU_STATE_BLOCKED_MAILBOX);
	}
out:
	sl_unlock(&vm->lock);

	return return_code;
}

/**
 * Retrieves the next VM whose mailbox became writable. For a VM to be notified
 * by this function, the caller must have called api_mailbox_send before with
 * the notify argument set to true, and this call must have failed because the
 * mailbox was not available.
 *
 * It should be called repeatedly to retrieve a list of VMs.
 *
 * Returns -1 if no VM became writable, or the id of the VM whose mailbox
 * became writable.
 */
int64_t api_mailbox_writable_get(const struct vcpu *current)
{
	struct vm *vm = current->vm;
	struct wait_entry *entry;
	int64_t ret;

	sl_lock(&vm->lock);
	if (list_empty(&vm->mailbox.ready_list)) {
		ret = -1;
		goto exit;
	}

	entry = CONTAINER_OF(vm->mailbox.ready_list.next, struct wait_entry,
			     ready_links);
	list_remove(&entry->ready_links);
	ret = vm_id_for_wait_entry(vm, entry);

exit:
	sl_unlock(&vm->lock);
	return ret;
}

/**
 * Retrieves the next VM waiting to be notified that the mailbox of the
 * specified VM became writable. Only primary VMs are allowed to call this.
 *
 * Returns -1 on failure or if there are no waiters; the VM id of the next
 * waiter otherwise.
 */
int64_t api_mailbox_waiter_get(ffa_vm_id_t vm_id, const struct vcpu *current)
{
	struct vm *vm;
	struct vm_locked locked;
	struct wait_entry *entry;
	struct vm *waiting_vm;

	/* Only primary VMs are allowed to call this function. */
	if (current->vm->id != HF_PRIMARY_VM_ID) {
		return -1;
	}

	vm = vm_find(vm_id);
	if (vm == NULL) {
		return -1;
	}

	/* Check if there are outstanding notifications from given VM. */
	locked = vm_lock(vm);
	entry = api_fetch_waiter(locked);
	vm_unlock(&locked);

	if (entry == NULL) {
		return -1;
	}

	/* Enqueue notification to waiting VM. */
	waiting_vm = entry->waiting_vm;

	sl_lock(&waiting_vm->lock);
	if (list_empty(&entry->ready_links)) {
		list_append(&waiting_vm->mailbox.ready_list,
			    &entry->ready_links);
	}
	sl_unlock(&waiting_vm->lock);

	return waiting_vm->id;
}

/**
 * Releases the caller's mailbox so that a new message can be received. The
 * caller must have copied out all data they wish to preserve as new messages
 * will overwrite the old and will arrive asynchronously.
 *
 * Returns:
 *  - FFA_ERROR FFA_DENIED on failure, if the mailbox hasn't been read.
 *  - FFA_SUCCESS on success if no further action is needed.
 *  - FFA_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters. Waiters should be retrieved by calling
 *    hf_mailbox_waiter_get.
 */
struct ffa_value api_ffa_rx_release(struct vcpu *current, struct vcpu **next)
{
	struct vm *vm = current->vm;
	struct vm_locked locked;
	struct ffa_value ret;

	locked = vm_lock(vm);
	switch (vm->mailbox.state) {
	case MAILBOX_STATE_EMPTY:
	case MAILBOX_STATE_RECEIVED:
		ret = ffa_error(FFA_DENIED);
		break;

	case MAILBOX_STATE_READ:
		ret = api_waiter_result(locked, current, next);
		vm->mailbox.state = MAILBOX_STATE_EMPTY;
		break;
	}
	vm_unlock(&locked);

	return ret;
}

/**
 * Enables or disables a given interrupt ID for the calling vCPU.
 *
 * Returns 0 on success, or -1 if the intid is invalid.
 */
int64_t api_interrupt_enable(uint32_t intid, bool enable,
			     enum interrupt_type type, struct vcpu *current)
{
	struct vcpu_locked current_locked;
	uint32_t intid_index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t intid_shift = intid % INTERRUPT_REGISTER_BITS;
	uint32_t intid_mask = 1U << intid_shift;

	if (intid >= HF_NUM_INTIDS) {
		return -1;
	}

	current_locked = vcpu_lock(current);
	if (enable) {
		/*
		 * If it is pending and was not enabled before, increment the
		 * count.
		 */
		if (current->interrupts.interrupt_pending[intid_index] &
		    ~current->interrupts.interrupt_enabled[intid_index] &
		    intid_mask) {
			if ((current->interrupts.interrupt_type[intid_index] &
			     intid_mask) ==
			    (INTERRUPT_TYPE_IRQ << intid_shift)) {
				vcpu_irq_count_increment(current_locked);
			} else {
				vcpu_fiq_count_increment(current_locked);
			}
		}
		current->interrupts.interrupt_enabled[intid_index] |=
			intid_mask;

		if (type == INTERRUPT_TYPE_IRQ) {
			current->interrupts.interrupt_type[intid_index] &=
				~intid_mask;
		} else if (type == INTERRUPT_TYPE_FIQ) {
			current->interrupts.interrupt_type[intid_index] |=
				intid_mask;
		}
	} else {
		/*
		 * If it is pending and was enabled before, decrement the count.
		 */
		if (current->interrupts.interrupt_pending[intid_index] &
		    current->interrupts.interrupt_enabled[intid_index] &
		    intid_mask) {
			if ((current->interrupts.interrupt_type[intid_index] &
			     intid_mask) ==
			    (INTERRUPT_TYPE_IRQ << intid_shift)) {
				vcpu_irq_count_decrement(current_locked);
			} else {
				vcpu_fiq_count_decrement(current_locked);
			}
		}
		current->interrupts.interrupt_enabled[intid_index] &=
			~intid_mask;
		current->interrupts.interrupt_type[intid_index] &= ~intid_mask;
	}

	vcpu_unlock(&current_locked);
	return 0;
}

/**
 * Returns the ID of the next pending interrupt for the calling vCPU, and
 * acknowledges it (i.e. marks it as no longer pending). Returns
 * HF_INVALID_INTID if there are no pending interrupts.
 */
uint32_t api_interrupt_get(struct vcpu *current)
{
	uint8_t i;
	uint32_t first_interrupt = HF_INVALID_INTID;
	struct vcpu_locked current_locked;

	/*
	 * Find the first enabled and pending interrupt ID, return it, and
	 * deactivate it.
	 */
	current_locked = vcpu_lock(current);
	for (i = 0; i < HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS; ++i) {
		uint32_t enabled_and_pending =
			current->interrupts.interrupt_enabled[i] &
			current->interrupts.interrupt_pending[i];

		if (enabled_and_pending != 0) {
			uint8_t bit_index = ctz(enabled_and_pending);
			uint32_t intid_mask = 1U << bit_index;

			/*
			 * Mark it as no longer pending and decrement the count.
			 */
			current->interrupts.interrupt_pending[i] &= ~intid_mask;

			if ((current->interrupts.interrupt_type[i] &
			     intid_mask) == (INTERRUPT_TYPE_IRQ << bit_index)) {
				vcpu_irq_count_decrement(current_locked);
			} else {
				vcpu_fiq_count_decrement(current_locked);
			}

			first_interrupt =
				i * INTERRUPT_REGISTER_BITS + bit_index;
			break;
		}
	}

	vcpu_unlock(&current_locked);
	return first_interrupt;
}

/**
 * Returns whether the current vCPU is allowed to inject an interrupt into the
 * given VM and vCPU.
 */
static inline bool is_injection_allowed(uint32_t target_vm_id,
					struct vcpu *current)
{
	uint32_t current_vm_id = current->vm->id;

	/*
	 * The primary VM is allowed to inject interrupts into any VM. Secondary
	 * VMs are only allowed to inject interrupts into their own vCPUs.
	 */
	return current_vm_id == HF_PRIMARY_VM_ID ||
	       current_vm_id == target_vm_id;
}

/**
 * Injects a virtual interrupt of the given ID into the given target vCPU.
 * This doesn't cause the vCPU to actually be run immediately; it will be taken
 * when the vCPU is next run, which is up to the scheduler.
 *
 * Returns:
 *  - -1 on failure because the target VM or vCPU doesn't exist, the interrupt
 *    ID is invalid, or the current VM is not allowed to inject interrupts to
 *    the target VM.
 *  - 0 on success if no further action is needed.
 *  - 1 if it was called by the primary VM and the primary VM now needs to wake
 *    up or kick the target vCPU.
 */
int64_t api_interrupt_inject(ffa_vm_id_t target_vm_id,
			     ffa_vcpu_index_t target_vcpu_idx, uint32_t intid,
			     struct vcpu *current, struct vcpu **next)
{
	struct vcpu *target_vcpu;
	struct vm *target_vm = vm_find(target_vm_id);

	if (intid >= HF_NUM_INTIDS) {
		return -1;
	}

	if (target_vm == NULL) {
		return -1;
	}

	if (target_vcpu_idx >= target_vm->vcpu_count) {
		/* The requested vCPU must exist. */
		return -1;
	}

	if (!is_injection_allowed(target_vm_id, current)) {
		return -1;
	}

	target_vcpu = vm_get_vcpu(target_vm, target_vcpu_idx);

	dlog_verbose(
		"Injecting interrupt %u for VM %#x vCPU %u from VM %#x vCPU "
		"%u\n",
		intid, target_vm_id, target_vcpu_idx, current->vm->id,
		vcpu_index(current));
	return internal_interrupt_inject(target_vcpu, intid, current, next);
}

/** Returns the version of the implemented FF-A specification. */
struct ffa_value api_ffa_version(uint32_t requested_version)
{
	/*
	 * Ensure that both major and minor revision representation occupies at
	 * most 15 bits.
	 */
	static_assert(0x8000 > FFA_VERSION_MAJOR,
		      "Major revision representation takes more than 15 bits.");
	static_assert(0x10000 > FFA_VERSION_MINOR,
		      "Minor revision representation takes more than 16 bits.");
	if (requested_version & FFA_VERSION_RESERVED_BIT) {
		/* Invalid encoding, return an error. */
		return (struct ffa_value){.func = (uint32_t)FFA_NOT_SUPPORTED};
	}

	return ((struct ffa_value){.func = FFA_VERSION_COMPILED});
}

int64_t api_debug_log(char c, struct vcpu *current)
{
	bool flush;
	struct vm *vm = current->vm;
	struct vm_locked vm_locked = vm_lock(vm);

	if (c == '\n' || c == '\0') {
		flush = true;
	} else {
		vm->log_buffer[vm->log_buffer_length++] = c;
		flush = (vm->log_buffer_length == sizeof(vm->log_buffer));
	}

	if (flush) {
		dlog_flush_vm_buffer(vm->id, vm->log_buffer,
				     vm->log_buffer_length);
		vm->log_buffer_length = 0;
	}

	vm_unlock(&vm_locked);

	return 0;
}

/**
 * Discovery function returning information about the implementation of optional
 * FF-A interfaces.
 */
struct ffa_value api_ffa_features(uint32_t function_id)
{
	switch (function_id) {
	case FFA_ERROR_32:
	case FFA_SUCCESS_32:
	case FFA_INTERRUPT_32:
	case FFA_VERSION_32:
	case FFA_FEATURES_32:
	case FFA_RX_RELEASE_32:
	case FFA_RXTX_MAP_64:
	case FFA_RXTX_UNMAP_32:
	case FFA_PARTITION_INFO_GET_32:
	case FFA_ID_GET_32:
	case FFA_MSG_POLL_32:
	case FFA_MSG_WAIT_32:
	case FFA_YIELD_32:
	case FFA_RUN_32:
	case FFA_MSG_SEND_32:
	case FFA_MEM_DONATE_32:
	case FFA_MEM_LEND_32:
	case FFA_MEM_SHARE_32:
	case FFA_MEM_RETRIEVE_REQ_32:
	case FFA_MEM_RETRIEVE_RESP_32:
	case FFA_MEM_RELINQUISH_32:
	case FFA_MEM_RECLAIM_32:
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
	/* FF-A v1.1 features. */
	case FFA_SPM_ID_GET_32:
#endif
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	default:
		return ffa_error(FFA_NOT_SUPPORTED);
	}
}

/**
 * FF-A specification states that x2/w2 Must Be Zero for direct messaging
 * interfaces.
 */
static inline bool api_ffa_dir_msg_is_arg2_zero(struct ffa_value args)
{
	return args.arg2 == 0U;
}

/**
 * Limits size of arguments in ffa_value structure to 32-bit.
 */
static struct ffa_value api_ffa_value_copy32(struct ffa_value args)
{
	return (struct ffa_value){
		.func = (uint32_t)args.func,
		.arg1 = (uint32_t)args.arg1,
		.arg2 = (uint32_t)0,
		.arg3 = (uint32_t)args.arg3,
		.arg4 = (uint32_t)args.arg4,
		.arg5 = (uint32_t)args.arg5,
		.arg6 = (uint32_t)args.arg6,
		.arg7 = (uint32_t)args.arg7,
	};
}

/**
 * Helper to copy direct message payload, depending on SMC used and expected
 * registers size.
 */
static struct ffa_value api_ffa_dir_msg_value(struct ffa_value args)
{
	if (args.func == FFA_MSG_SEND_DIRECT_REQ_32 ||
	    args.func == FFA_MSG_SEND_DIRECT_RESP_32) {
		return api_ffa_value_copy32(args);
	}

	return (struct ffa_value){
		.func = args.func,
		.arg1 = args.arg1,
		.arg2 = 0,
		.arg3 = args.arg3,
		.arg4 = args.arg4,
		.arg5 = args.arg5,
		.arg6 = args.arg6,
		.arg7 = args.arg7,
	};
}

/**
 * Send an FF-A direct message request.
 */
struct ffa_value api_ffa_msg_send_direct_req(ffa_vm_id_t sender_vm_id,
					     ffa_vm_id_t receiver_vm_id,
					     struct ffa_value args,
					     struct vcpu *current,
					     struct vcpu **next)
{
	struct ffa_value ret;
	struct vm *receiver_vm;
	struct vcpu *receiver_vcpu;
	struct two_vcpu_locked vcpus_locked;

	if (!api_ffa_dir_msg_is_arg2_zero(args)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (!plat_ffa_is_direct_request_valid(current, sender_vm_id,
					      receiver_vm_id)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (plat_ffa_direct_request_forward(receiver_vm_id, args, &ret)) {
		return ret;
	}

	ret = (struct ffa_value){.func = FFA_INTERRUPT_32};

	receiver_vm = vm_find(receiver_vm_id);
	if (receiver_vm == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Per PSA FF-A EAC spec section 4.4.1 the firmware framework supports
	 * UP (migratable) or MP partitions with a number of vCPUs matching the
	 * number of PEs in the system. It further states that MP partitions
	 * accepting direct request messages cannot migrate.
	 */
	receiver_vcpu = api_ffa_get_vm_vcpu(receiver_vm, current);
	if (receiver_vcpu == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	vcpus_locked = vcpu_lock_both(receiver_vcpu, current);

	/*
	 * If destination vCPU is executing or already received an
	 * FFA_MSG_SEND_DIRECT_REQ then return to caller hinting recipient is
	 * busy. There is a brief period of time where the vCPU state has
	 * changed but regs_available is still false thus consider this case as
	 * the vCPU not yet ready to receive a direct message request.
	 */
	if (is_ffa_direct_msg_request_ongoing(vcpus_locked.vcpu1) ||
	    receiver_vcpu->state == VCPU_STATE_RUNNING ||
	    !receiver_vcpu->regs_available) {
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	if (atomic_load_explicit(&receiver_vcpu->vm->aborting,
				 memory_order_relaxed)) {
		if (receiver_vcpu->state != VCPU_STATE_ABORTED) {
			dlog_notice("Aborting VM %#x vCPU %u\n",
				    receiver_vcpu->vm->id,
				    vcpu_index(receiver_vcpu));
			receiver_vcpu->state = VCPU_STATE_ABORTED;
		}

		ret = ffa_error(FFA_ABORTED);
		goto out;
	}

	switch (receiver_vcpu->state) {
	case VCPU_STATE_OFF:
	case VCPU_STATE_RUNNING:
	case VCPU_STATE_ABORTED:
	case VCPU_STATE_READY:
	case VCPU_STATE_BLOCKED_INTERRUPT:
		ret = ffa_error(FFA_BUSY);
		goto out;
	case VCPU_STATE_BLOCKED_MAILBOX:
		/*
		 * Expect target vCPU to be blocked after having called
		 * ffa_msg_wait or sent a direct message response.
		 */
		break;
	}

	/* Inject timer interrupt if any pending */
	if (arch_timer_pending(&receiver_vcpu->regs)) {
		api_interrupt_inject_locked(vcpus_locked.vcpu1,
					    HF_VIRTUAL_TIMER_INTID, current,
					    NULL);

		arch_timer_mask(&receiver_vcpu->regs);
	}

	/* The receiver vCPU runs upon direct message invocation */
	receiver_vcpu->cpu = current->cpu;
	receiver_vcpu->state = VCPU_STATE_RUNNING;
	receiver_vcpu->regs_available = false;
	receiver_vcpu->direct_request_origin_vm_id = sender_vm_id;

	arch_regs_set_retval(&receiver_vcpu->regs, api_ffa_dir_msg_value(args));

	current->state = VCPU_STATE_BLOCKED_MAILBOX;

	/* Switch to receiver vCPU targeted to by direct msg request */
	*next = receiver_vcpu;

	/*
	 * Since this flow will lead to a VM switch, the return value will not
	 * be applied to current vCPU.
	 */

out:
	sl_unlock(&receiver_vcpu->lock);
	sl_unlock(&current->lock);

	return ret;
}

/**
 * Send an FF-A direct message response.
 */
struct ffa_value api_ffa_msg_send_direct_resp(ffa_vm_id_t sender_vm_id,
					      ffa_vm_id_t receiver_vm_id,
					      struct ffa_value args,
					      struct vcpu *current,
					      struct vcpu **next)
{
	struct vcpu_locked current_locked;

	if (!api_ffa_dir_msg_is_arg2_zero(args)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	struct ffa_value to_ret = api_ffa_dir_msg_value(args);

	if (!plat_ffa_is_direct_response_valid(current, sender_vm_id,
					       receiver_vm_id)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	current_locked = vcpu_lock(current);
	if (api_ffa_is_managed_exit_ongoing(current_locked)) {
		/*
		 * No need for REQ/RESP state management as managed exit does
		 * not have corresponding REQ pair.
		 */
		if (receiver_vm_id != HF_PRIMARY_VM_ID) {
			vcpu_unlock(&current_locked);
			return ffa_error(FFA_DENIED);
		}

		plat_interrupts_set_priority_mask(0xff);
		current->processing_managed_exit = false;
	} else {
		/*
		 * Ensure the terminating FFA_MSG_SEND_DIRECT_REQ had a
		 * defined originator.
		 */
		if (!is_ffa_direct_msg_request_ongoing(current_locked)) {
			/*
			 * Sending direct response but direct request origin
			 * vCPU is not set.
			 */
			vcpu_unlock(&current_locked);
			return ffa_error(FFA_DENIED);
		}

		if (current->direct_request_origin_vm_id != receiver_vm_id) {
			vcpu_unlock(&current_locked);
			return ffa_error(FFA_DENIED);
		}
	}

	/* Clear direct request origin for the caller. */
	current->direct_request_origin_vm_id = HF_INVALID_VM_ID;

	vcpu_unlock(&current_locked);

	if (!vm_id_is_current_world(receiver_vm_id)) {
		*next = api_switch_to_other_world(current, to_ret,
						  VCPU_STATE_BLOCKED_MAILBOX);
	} else if (receiver_vm_id == HF_PRIMARY_VM_ID) {
		*next = api_switch_to_primary(current, to_ret,
					      VCPU_STATE_BLOCKED_MAILBOX);
	} else if (vm_id_is_current_world(receiver_vm_id)) {
		/*
		 * It is expected the receiver_vm_id to be from an SP, otherwise
		 * 'arch_other_world_is_direct_response_valid' should have
		 * made function return error before getting to this point.
		 */
		*next = api_switch_to_vm(current, to_ret,
					 VCPU_STATE_BLOCKED_MAILBOX,
					 receiver_vm_id);
	} else {
		panic("Invalid direct message response invocation");
	}

	return (struct ffa_value){.func = FFA_INTERRUPT_32};
}

static bool api_memory_region_check_flags(
	struct ffa_memory_region *memory_region, uint32_t share_func)
{
	switch (share_func) {
	case FFA_MEM_SHARE_32:
		if ((memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR) !=
		    0U) {
			return false;
		}
		/* Intentional fall-through */
	case FFA_MEM_LEND_32:
	case FFA_MEM_DONATE_32: {
		/* Bits 31:2 Must Be Zero. */
		ffa_memory_receiver_flags_t to_mask =
			~(FFA_MEMORY_REGION_FLAG_CLEAR |
			  FFA_MEMORY_REGION_FLAG_TIME_SLICE);

		if ((memory_region->flags & to_mask) != 0U) {
			return false;
		}
		break;
	}
	default:
		panic("Check for mem send calls only.\n");
	}

	/* Last check reserved values are 0 */
	return true;
}

struct ffa_value api_ffa_mem_send(uint32_t share_func, uint32_t length,
				  uint32_t fragment_length, ipaddr_t address,
				  uint32_t page_count, struct vcpu *current)
{
	struct vm *from = current->vm;
	struct vm *to;
	const void *from_msg;
	struct ffa_memory_region *memory_region;
	struct ffa_value ret;

	if (ipa_addr(address) != 0 || page_count != 0) {
		/*
		 * Hafnium only supports passing the descriptor in the TX
		 * mailbox.
		 */
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (fragment_length > length) {
		dlog_verbose(
			"Fragment length %d greater than total length %d.\n",
			fragment_length, length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if (fragment_length < sizeof(struct ffa_memory_region) +
				      sizeof(struct ffa_memory_access)) {
		dlog_verbose(
			"Initial fragment length %d smaller than header size "
			"%d.\n",
			fragment_length,
			sizeof(struct ffa_memory_region) +
				sizeof(struct ffa_memory_access));
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check that the sender has configured its send buffer. If the TX
	 * mailbox at from_msg is configured (i.e. from_msg != NULL) then it can
	 * be safely accessed after releasing the lock since the TX mailbox
	 * address can only be configured once.
	 */
	sl_lock(&from->lock);
	from_msg = from->mailbox.send;
	sl_unlock(&from->lock);

	if (from_msg == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Copy the memory region descriptor to a fresh page from the memory
	 * pool. This prevents the sender from changing it underneath us, and
	 * also lets us keep it around in the share state table if needed.
	 */
	if (fragment_length > HF_MAILBOX_SIZE ||
	    fragment_length > MM_PPOOL_ENTRY_SIZE) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	memory_region = (struct ffa_memory_region *)mpool_alloc(&api_page_pool);
	if (memory_region == NULL) {
		dlog_verbose("Failed to allocate memory region copy.\n");
		return ffa_error(FFA_NO_MEMORY);
	}
	memcpy_s(memory_region, MM_PPOOL_ENTRY_SIZE, from_msg, fragment_length);

	/* The sender must match the caller. */
	if (memory_region->sender != from->id) {
		dlog_verbose("Memory region sender doesn't match caller.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (!api_memory_region_check_flags(memory_region, share_func)) {
		dlog_verbose(
			"Memory region reserved arguments must be zero.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->receiver_count != 1) {
		/* Hafnium doesn't support multi-way memory sharing for now. */
		dlog_verbose(
			"Multi-way memory sharing not supported (got %d "
			"endpoint memory access descriptors, expected 1).\n",
			memory_region->receiver_count);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Ensure that the receiver VM exists and isn't the same as the sender.
	 */
	to = vm_find(memory_region->receivers[0].receiver_permissions.receiver);
	if (to == NULL || to == from) {
		dlog_verbose("Invalid receiver.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (to->id == HF_TEE_VM_ID) {
		/*
		 * The 'to' VM lock is only needed in the case that it is the
		 * TEE VM.
		 */
		struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

		if (msg_receiver_busy(vm_to_from_lock.vm1, from, false)) {
			ret = ffa_error(FFA_BUSY);
			goto out_unlock;
		}

		ret = ffa_memory_tee_send(
			vm_to_from_lock.vm2, vm_to_from_lock.vm1, memory_region,
			length, fragment_length, share_func, &api_page_pool);
		/*
		 * ffa_tee_memory_send takes ownership of the memory_region, so
		 * make sure we don't free it.
		 */
		memory_region = NULL;

	out_unlock:
		vm_unlock(&vm_to_from_lock.vm1);
		vm_unlock(&vm_to_from_lock.vm2);
	} else {
		struct vm_locked from_locked = vm_lock(from);

		ret = ffa_memory_send(from_locked, memory_region, length,
				      fragment_length, share_func,
				      &api_page_pool);
		/*
		 * ffa_memory_send takes ownership of the memory_region, so
		 * make sure we don't free it.
		 */
		memory_region = NULL;

		vm_unlock(&from_locked);
	}

out:
	if (memory_region != NULL) {
		mpool_free(&api_page_pool, memory_region);
	}

	return ret;
}

struct ffa_value api_ffa_mem_retrieve_req(uint32_t length,
					  uint32_t fragment_length,
					  ipaddr_t address, uint32_t page_count,
					  struct vcpu *current)
{
	struct vm *to = current->vm;
	struct vm_locked to_locked;
	const void *to_msg;
	struct ffa_memory_region *retrieve_request;
	uint32_t message_buffer_size;
	struct ffa_value ret;

	if (ipa_addr(address) != 0 || page_count != 0) {
		/*
		 * Hafnium only supports passing the descriptor in the TX
		 * mailbox.
		 */
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (fragment_length != length) {
		dlog_verbose("Fragmentation not yet supported.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	retrieve_request =
		(struct ffa_memory_region *)cpu_get_buffer(current->cpu);
	message_buffer_size = cpu_get_buffer_size(current->cpu);
	if (length > HF_MAILBOX_SIZE || length > message_buffer_size) {
		dlog_verbose("Retrieve request too long.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	to_locked = vm_lock(to);
	to_msg = to->mailbox.send;

	if (to_msg == NULL) {
		dlog_verbose("TX buffer not setup.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Copy the retrieve request descriptor to an internal buffer, so that
	 * the caller can't change it underneath us.
	 */
	memcpy_s(retrieve_request, message_buffer_size, to_msg, length);

	if (msg_receiver_busy(to_locked, NULL, false)) {
		/*
		 * Can't retrieve memory information if the mailbox is not
		 * available.
		 */
		dlog_verbose("RX buffer not ready.\n");
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	ret = ffa_memory_retrieve(to_locked, retrieve_request, length,
				  &api_page_pool);

out:
	vm_unlock(&to_locked);
	return ret;
}

struct ffa_value api_ffa_mem_relinquish(struct vcpu *current)
{
	struct vm *from = current->vm;
	struct vm_locked from_locked;
	const void *from_msg;
	struct ffa_mem_relinquish *relinquish_request;
	uint32_t message_buffer_size;
	struct ffa_value ret;
	uint32_t length;

	from_locked = vm_lock(from);
	from_msg = from->mailbox.send;

	if (from_msg == NULL) {
		dlog_verbose("TX buffer not setup.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Calculate length from relinquish descriptor before copying. We will
	 * check again later to make sure it hasn't changed.
	 */
	length = sizeof(struct ffa_mem_relinquish) +
		 ((struct ffa_mem_relinquish *)from_msg)->endpoint_count *
			 sizeof(ffa_vm_id_t);
	/*
	 * Copy the relinquish descriptor to an internal buffer, so that the
	 * caller can't change it underneath us.
	 */
	relinquish_request =
		(struct ffa_mem_relinquish *)cpu_get_buffer(current->cpu);
	message_buffer_size = cpu_get_buffer_size(current->cpu);
	if (length > HF_MAILBOX_SIZE || length > message_buffer_size) {
		dlog_verbose("Relinquish message too long.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}
	memcpy_s(relinquish_request, message_buffer_size, from_msg, length);

	if (sizeof(struct ffa_mem_relinquish) +
		    relinquish_request->endpoint_count * sizeof(ffa_vm_id_t) !=
	    length) {
		dlog_verbose(
			"Endpoint count changed while copying to internal "
			"buffer.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	ret = ffa_memory_relinquish(from_locked, relinquish_request,
				    &api_page_pool);

out:
	vm_unlock(&from_locked);
	return ret;
}

struct ffa_value api_ffa_mem_reclaim(ffa_memory_handle_t handle,
				     ffa_memory_region_flags_t flags,
				     struct vcpu *current)
{
	struct vm *to = current->vm;
	struct ffa_value ret;

	if (plat_ffa_memory_handle_allocated_by_current_world(handle)) {
		struct vm_locked to_locked = vm_lock(to);

		ret = ffa_memory_reclaim(to_locked, handle, flags,
					 &api_page_pool);

		vm_unlock(&to_locked);
	} else {
		struct vm *from = vm_find(HF_TEE_VM_ID);
		struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

		ret = ffa_memory_tee_reclaim(vm_to_from_lock.vm1,
					     vm_to_from_lock.vm2, handle, flags,
					     &api_page_pool);

		vm_unlock(&vm_to_from_lock.vm1);
		vm_unlock(&vm_to_from_lock.vm2);
	}

	return ret;
}

struct ffa_value api_ffa_mem_frag_rx(ffa_memory_handle_t handle,
				     uint32_t fragment_offset,
				     ffa_vm_id_t sender_vm_id,
				     struct vcpu *current)
{
	struct vm *to = current->vm;
	struct vm_locked to_locked;
	struct ffa_value ret;

	/* Sender ID MBZ at virtual instance. */
	if (sender_vm_id != 0) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	to_locked = vm_lock(to);

	if (msg_receiver_busy(to_locked, NULL, false)) {
		/*
		 * Can't retrieve memory information if the mailbox is not
		 * available.
		 */
		dlog_verbose("RX buffer not ready.\n");
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	ret = ffa_memory_retrieve_continue(to_locked, handle, fragment_offset,
					   &api_page_pool);

out:
	vm_unlock(&to_locked);
	return ret;
}

struct ffa_value api_ffa_mem_frag_tx(ffa_memory_handle_t handle,
				     uint32_t fragment_length,
				     ffa_vm_id_t sender_vm_id,
				     struct vcpu *current)
{
	struct vm *from = current->vm;
	const void *from_msg;
	void *fragment_copy;
	struct ffa_value ret;

	/* Sender ID MBZ at virtual instance. */
	if (sender_vm_id != 0) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check that the sender has configured its send buffer. If the TX
	 * mailbox at from_msg is configured (i.e. from_msg != NULL) then it can
	 * be safely accessed after releasing the lock since the TX mailbox
	 * address can only be configured once.
	 */
	sl_lock(&from->lock);
	from_msg = from->mailbox.send;
	sl_unlock(&from->lock);

	if (from_msg == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Copy the fragment to a fresh page from the memory pool. This prevents
	 * the sender from changing it underneath us, and also lets us keep it
	 * around in the share state table if needed.
	 */
	if (fragment_length > HF_MAILBOX_SIZE ||
	    fragment_length > MM_PPOOL_ENTRY_SIZE) {
		dlog_verbose(
			"Fragment length %d larger than mailbox size %d.\n",
			fragment_length, HF_MAILBOX_SIZE);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	if (fragment_length < sizeof(struct ffa_memory_region_constituent) ||
	    fragment_length % sizeof(struct ffa_memory_region_constituent) !=
		    0) {
		dlog_verbose("Invalid fragment length %d.\n", fragment_length);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}
	fragment_copy = mpool_alloc(&api_page_pool);
	if (fragment_copy == NULL) {
		dlog_verbose("Failed to allocate fragment copy.\n");
		return ffa_error(FFA_NO_MEMORY);
	}
	memcpy_s(fragment_copy, MM_PPOOL_ENTRY_SIZE, from_msg, fragment_length);

	/*
	 * Hafnium doesn't support fragmentation of memory retrieve requests
	 * (because it doesn't support caller-specified mappings, so a request
	 * will never be larger than a single page), so this must be part of a
	 * memory send (i.e. donate, lend or share) request.
	 *
	 * We can tell from the handle whether the memory transaction is for the
	 * TEE or not.
	 */
	if ((handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	    FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
		struct vm_locked from_locked = vm_lock(from);

		ret = ffa_memory_send_continue(from_locked, fragment_copy,
					       fragment_length, handle,
					       &api_page_pool);
		/*
		 * `ffa_memory_send_continue` takes ownership of the
		 * fragment_copy, so we don't need to free it here.
		 */
		vm_unlock(&from_locked);
	} else {
		struct vm *to = vm_find(HF_TEE_VM_ID);
		struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

		/*
		 * The TEE RX buffer state is checked in
		 * `ffa_memory_tee_send_continue` rather than here, as we need
		 * to return `FFA_MEM_FRAG_RX` with the current offset rather
		 * than FFA_ERROR FFA_BUSY in case it is busy.
		 */

		ret = ffa_memory_tee_send_continue(
			vm_to_from_lock.vm2, vm_to_from_lock.vm1, fragment_copy,
			fragment_length, handle, &api_page_pool);
		/*
		 * `ffa_memory_tee_send_continue` takes ownership of the
		 * fragment_copy, so we don't need to free it here.
		 */

		vm_unlock(&vm_to_from_lock.vm1);
		vm_unlock(&vm_to_from_lock.vm2);
	}

	return ret;
}

struct ffa_value api_ffa_secondary_ep_register(ipaddr_t entry_point,
					       struct vcpu *current)
{
	struct vm_locked vm_locked;

	vm_locked = vm_lock(current->vm);
	vm_locked.vm->secondary_ep = entry_point;
	vm_unlock(&vm_locked);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value api_ffa_notification_bitmap_create(ffa_vm_id_t vm_id,
						    ffa_vcpu_count_t vcpu_count,
						    struct vcpu *current)
{
	if (!plat_ffa_is_notifications_create_valid(current, vm_id)) {
		dlog_verbose("Bitmap create for NWd VM IDs only (%x).\n",
			     vm_id);
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	return plat_ffa_notifications_bitmap_create(vm_id, vcpu_count);
}

struct ffa_value api_ffa_notification_bitmap_destroy(ffa_vm_id_t vm_id,
						     struct vcpu *current)
{
	/*
	 * Validity of use of this interface is the same as for bitmap create.
	 */
	if (!plat_ffa_is_notifications_create_valid(current, vm_id)) {
		dlog_verbose("Bitmap destroy for NWd VM IDs only (%x).\n",
			     vm_id);
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	return plat_ffa_notifications_bitmap_destroy(vm_id);
}

struct ffa_value api_ffa_notification_update_bindings(
	ffa_vm_id_t sender_vm_id, ffa_vm_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, bool is_bind,
	struct vcpu *current)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	struct vm_locked receiver_locked;
	const bool is_per_vcpu = (flags & FFA_NOTIFICATION_FLAG_PER_VCPU) != 0U;
	const ffa_vm_id_t id_to_update =
		is_bind ? sender_vm_id : HF_INVALID_VM_ID;
	const ffa_vm_id_t id_to_validate =
		is_bind ? HF_INVALID_VM_ID : sender_vm_id;

	if (!plat_ffa_is_notifications_bind_valid(current, sender_vm_id,
						  receiver_vm_id)) {
		dlog_verbose("Invalid use of notifications bind interface.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (notifications == 0U) {
		dlog_verbose("No notifications have been specified.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/**
	 * This check assumes receiver is the current VM, and has been enforced
	 * by 'plat_ffa_is_notifications_bind_valid'.
	 */
	receiver_locked = plat_ffa_vm_find_locked(receiver_vm_id);

	if (receiver_locked.vm == NULL) {
		dlog_verbose("Receiver doesn't exist!\n");
		return ffa_error(FFA_DENIED);
	}

	if (!vm_are_notifications_enabled(receiver_locked)) {
		dlog_verbose("Notifications are not enabled.\n");
		ret = ffa_error(FFA_NOT_SUPPORTED);
		goto out;
	}

	if (is_bind && vm_id_is_current_world(sender_vm_id) &&
	    vm_find(sender_vm_id) == NULL) {
		dlog_verbose("Sender VM does not exist!\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Can't bind/unbind notifications if at least one is bound to a
	 * different sender.
	 */
	if (!vm_notifications_validate_bound_sender(
		    receiver_locked, plat_ffa_is_vm_id(sender_vm_id),
		    id_to_validate, notifications)) {
		dlog_verbose("Notifications are bound to other sender.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/**
	 * Check if there is a pending notification within those specified in
	 * the bitmap.
	 */
	if (vm_are_notifications_pending(receiver_locked,
					 plat_ffa_is_vm_id(sender_vm_id),
					 notifications)) {
		dlog_verbose("Notifications within '%x' pending.\n",
			     notifications);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	vm_notifications_update_bindings(
		receiver_locked, plat_ffa_is_vm_id(sender_vm_id), id_to_update,
		notifications, is_per_vcpu && is_bind);

out:
	vm_unlock(&receiver_locked);
	return ret;
}
