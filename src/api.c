/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/api.h"

#include "hf/arch/cpu.h"
#include "hf/arch/tee.h"
#include "hf/arch/timer.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa_internal.h"
#include "hf/ffa_memory.h"
#include "hf/mm.h"
#include "hf/plat/console.h"
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
 * Switches the physical CPU back to the corresponding vCPU of the primary VM.
 *
 * This triggers the scheduling logic to run. Run in the context of secondary VM
 * to cause FFA_RUN to return and the primary VM to regain control of the CPU.
 */
static struct vcpu *api_switch_to_primary(struct vcpu *current,
					  struct ffa_value primary_ret,
					  enum vcpu_state secondary_state)
{
	struct vm *primary = vm_find(HF_PRIMARY_VM_ID);
	struct vcpu *next = vm_get_vcpu(primary, cpu_index(current->cpu));

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

	/* Set the return value for the primary VM's call to HF_VCPU_RUN. */
	arch_regs_set_retval(&next->regs, primary_ret);

	/* Mark the current vCPU as waiting. */
	sl_lock(&current->lock);
	current->state = secondary_state;
	sl_unlock(&current->lock);

	return next;
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
void api_yield(struct vcpu *current, struct vcpu **next)
{
	struct ffa_value primary_ret = {
		.func = FFA_YIELD_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	if (current->vm->id == HF_PRIMARY_VM_ID) {
		/* NOOP on the primary as it makes the scheduling decisions. */
		return;
	}

	*next = api_switch_to_primary(current, primary_ret, VCPU_STATE_READY);
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

	dlog_notice("Aborting VM %u vCPU %u\n", current->vm->id,
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

			/* Hafnium only supports indirect messaging. */
			partitions[vm_count].properties =
				FFA_PARTITION_INDIRECT_MSG;

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
static int64_t internal_interrupt_inject_locked(
	struct vcpu_locked target_locked, uint32_t intid, struct vcpu *current,
	struct vcpu **next)
{
	uint32_t intid_index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t intid_mask = 1U << (intid % INTERRUPT_REGISTER_BITS);
	int64_t ret = 0;

	/*
	 * We only need to change state and (maybe) trigger a virtual IRQ if it
	 * is enabled and was not previously pending. Otherwise we can skip
	 * everything except setting the pending bit.
	 *
	 * If you change this logic make sure to update the need_vm_lock logic
	 * above to match.
	 */
	if (!(target_locked.vcpu->interrupts.interrupt_enabled[intid_index] &
	      ~target_locked.vcpu->interrupts.interrupt_pending[intid_index] &
	      intid_mask)) {
		goto out;
	}

	/* Increment the count. */
	target_locked.vcpu->interrupts.enabled_and_pending_count++;

	/*
	 * Only need to update state if there was not already an
	 * interrupt enabled and pending.
	 */
	if (target_locked.vcpu->interrupts.enabled_and_pending_count != 1) {
		goto out;
	}

	if (current->vm->id == HF_PRIMARY_VM_ID) {
		/*
		 * If the call came from the primary VM, let it know that it
		 * should run or kick the target vCPU.
		 */
		ret = 1;
	} else if (current != target_locked.vcpu && next != NULL) {
		*next = api_wake_up(current, target_locked.vcpu);
	}

out:
	/* Either way, make it pending. */
	target_locked.vcpu->interrupts.interrupt_pending[intid_index] |=
		intid_mask;

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
	ret = internal_interrupt_inject_locked(target_locked, intid, current,
					       next);
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
	sl_lock(&vcpu->lock);

	/* The VM needs to be locked to deliver mailbox messages. */
	need_vm_lock = vcpu->state == VCPU_STATE_BLOCKED_MAILBOX;
	if (need_vm_lock) {
		sl_unlock(&vcpu->lock);
		sl_lock(&vcpu->vm->lock);
		sl_lock(&vcpu->lock);
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
			dlog_notice("Aborting VM %u vCPU %u\n", vcpu->vm->id,
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
		if (vcpu->interrupts.enabled_and_pending_count > 0) {
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
	sl_unlock(&vcpu->lock);
	if (need_vm_lock) {
		sl_unlock(&vcpu->vm->lock);
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
 * Determines the value to be returned by api_vm_configure and ffa_rx_release
 * after they've succeeded. If a secondary VM is running and there are waiters,
 * it also switches back to the primary VM for it to wake waiters up.
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
 * Configures the hypervisor's stage-1 view of the send and receive pages. The
 * stage-1 page tables must be locked so memory cannot be taken by another core
 * which could result in this transaction being unable to roll back in the case
 * of an error.
 */
static bool api_vm_configure_stage1(struct vm_locked vm_locked,
				    paddr_t pa_send_begin, paddr_t pa_send_end,
				    paddr_t pa_recv_begin, paddr_t pa_recv_end,
				    struct mpool *local_page_pool)
{
	bool ret;
	struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();

	/* Map the send page as read-only in the hypervisor address space. */
	vm_locked.vm->mailbox.send =
		mm_identity_map(mm_stage1_locked, pa_send_begin, pa_send_end,
				MM_MODE_R, local_page_pool);
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
				MM_MODE_W, local_page_pool);
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
	mm_unlock_stage1(&mm_stage1_locked);

	return ret;
}

/**
 * Configures the send and receive pages in the VM stage-2 and hypervisor
 * stage-1 page tables. Locking of the page tables combined with a local memory
 * pool ensures there will always be enough memory to recover from any errors
 * that arise.
 */
static bool api_vm_configure_pages(struct vm_locked vm_locked,
				   paddr_t pa_send_begin, paddr_t pa_send_end,
				   uint32_t orig_send_mode,
				   paddr_t pa_recv_begin, paddr_t pa_recv_end,
				   uint32_t orig_recv_mode)
{
	bool ret;
	struct mpool local_page_pool;

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if any
	 * stage of the process fails.
	 */
	mpool_init_with_fallback(&local_page_pool, &api_page_pool);

	/* Take memory ownership away from the VM and mark as shared. */
	if (!vm_identity_map(
		    vm_locked, pa_send_begin, pa_send_end,
		    MM_MODE_UNOWNED | MM_MODE_SHARED | MM_MODE_R | MM_MODE_W,
		    &local_page_pool, NULL)) {
		goto fail;
	}

	if (!vm_identity_map(vm_locked, pa_recv_begin, pa_recv_end,
			     MM_MODE_UNOWNED | MM_MODE_SHARED | MM_MODE_R,
			     &local_page_pool, NULL)) {
		/* TODO: partial defrag of failed range. */
		/* Recover any memory consumed in failed mapping. */
		mm_vm_defrag(&vm_locked.vm->ptable, &local_page_pool);
		goto fail_undo_send;
	}

	if (!api_vm_configure_stage1(vm_locked, pa_send_begin, pa_send_end,
				     pa_recv_begin, pa_recv_end,
				     &local_page_pool)) {
		goto fail_undo_send_and_recv;
	}

	ret = true;
	goto out;

	/*
	 * The following mappings will not require more memory than is available
	 * in the local pool.
	 */
fail_undo_send_and_recv:
	CHECK(vm_identity_map(vm_locked, pa_recv_begin, pa_recv_end,
			      orig_recv_mode, &local_page_pool, NULL));

fail_undo_send:
	CHECK(vm_identity_map(vm_locked, pa_send_begin, pa_send_end,
			      orig_send_mode, &local_page_pool, NULL));

fail:
	ret = false;

out:
	mpool_fini(&local_page_pool);

	return ret;
}

/**
 * Configures the VM to send/receive data through the specified pages. The pages
 * must not be shared.
 *
 * Returns:
 *  - FFA_ERROR FFA_INVALID_PARAMETERS if the given addresses are not properly
 *    aligned or are the same.
 *  - FFA_ERROR FFA_NO_MEMORY if the hypervisor was unable to map the buffers
 *    due to insuffient page table memory.
 *  - FFA_ERROR FFA_DENIED if the pages are already mapped or are not owned by
 *    the caller.
 *  - FFA_SUCCESS on success if no further action is needed.
 *  - FFA_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters.
 */
struct ffa_value api_ffa_rxtx_map(ipaddr_t send, ipaddr_t recv,
				  uint32_t page_count, struct vcpu *current,
				  struct vcpu **next)
{
	struct vm *vm = current->vm;
	struct vm_locked vm_locked;
	paddr_t pa_send_begin;
	paddr_t pa_send_end;
	paddr_t pa_recv_begin;
	paddr_t pa_recv_end;
	uint32_t orig_send_mode;
	uint32_t orig_recv_mode;
	struct ffa_value ret;

	/* Hafnium only supports a fixed size of RX/TX buffers. */
	if (page_count != HF_MAILBOX_SIZE / FFA_PAGE_SIZE) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Fail if addresses are not page-aligned. */
	if (!is_aligned(ipa_addr(send), PAGE_SIZE) ||
	    !is_aligned(ipa_addr(recv), PAGE_SIZE)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Convert to physical addresses. */
	pa_send_begin = pa_from_ipa(send);
	pa_send_end = pa_add(pa_send_begin, HF_MAILBOX_SIZE);

	pa_recv_begin = pa_from_ipa(recv);
	pa_recv_end = pa_add(pa_recv_begin, HF_MAILBOX_SIZE);

	/* Fail if the same page is used for the send and receive pages. */
	if (pa_addr(pa_send_begin) == pa_addr(pa_recv_begin)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * The hypervisor's memory map must be locked for the duration of this
	 * operation to ensure there will be sufficient memory to recover from
	 * any failures.
	 *
	 * TODO: the scope can be reduced but will require restructuring to
	 *       keep a single unlock point.
	 */
	vm_locked = vm_lock(vm);

	/* We only allow these to be setup once. */
	if (vm->mailbox.send || vm->mailbox.recv) {
		ret = ffa_error(FFA_DENIED);
		goto exit;
	}

	/*
	 * Ensure the pages are valid, owned and exclusive to the VM and that
	 * the VM has the required access to the memory.
	 */
	if (!mm_vm_get_mode(&vm->ptable, send, ipa_add(send, PAGE_SIZE),
			    &orig_send_mode) ||
	    !api_mode_valid_owned_and_exclusive(orig_send_mode) ||
	    (orig_send_mode & MM_MODE_R) == 0 ||
	    (orig_send_mode & MM_MODE_W) == 0) {
		ret = ffa_error(FFA_DENIED);
		goto exit;
	}

	if (!mm_vm_get_mode(&vm->ptable, recv, ipa_add(recv, PAGE_SIZE),
			    &orig_recv_mode) ||
	    !api_mode_valid_owned_and_exclusive(orig_recv_mode) ||
	    (orig_recv_mode & MM_MODE_R) == 0) {
		ret = ffa_error(FFA_DENIED);
		goto exit;
	}

	if (!api_vm_configure_pages(vm_locked, pa_send_begin, pa_send_end,
				    orig_send_mode, pa_recv_begin, pa_recv_end,
				    orig_recv_mode)) {
		ret = ffa_error(FFA_NO_MEMORY);
		goto exit;
	}

	/* Tell caller about waiters, if any. */
	ret = api_waiter_result(vm_locked, current, next);

exit:
	vm_unlock(&vm_locked);

	return ret;
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

		ret = arch_tee_call(call);
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
	bool interrupted;

	sl_lock(&current->lock);

	/*
	 * Don't block if there are enabled and pending interrupts, to match
	 * behaviour of wait_for_interrupt.
	 */
	interrupted = (current->interrupts.enabled_and_pending_count > 0);

	sl_unlock(&current->lock);

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
	struct vm *vm = current->vm;
	struct ffa_value return_code;

	/*
	 * The primary VM will receive messages as a status code from running
	 * vCPUs and must not call this function.
	 */
	if (vm->id == HF_PRIMARY_VM_ID) {
		return ffa_error(FFA_NOT_SUPPORTED);
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

	/* Switch back to primary VM to block. */
	{
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
int64_t api_interrupt_enable(uint32_t intid, bool enable, struct vcpu *current)
{
	uint32_t intid_index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t intid_mask = 1U << (intid % INTERRUPT_REGISTER_BITS);

	if (intid >= HF_NUM_INTIDS) {
		return -1;
	}

	sl_lock(&current->lock);
	if (enable) {
		/*
		 * If it is pending and was not enabled before, increment the
		 * count.
		 */
		if (current->interrupts.interrupt_pending[intid_index] &
		    ~current->interrupts.interrupt_enabled[intid_index] &
		    intid_mask) {
			current->interrupts.enabled_and_pending_count++;
		}
		current->interrupts.interrupt_enabled[intid_index] |=
			intid_mask;
	} else {
		/*
		 * If it is pending and was enabled before, decrement the count.
		 */
		if (current->interrupts.interrupt_pending[intid_index] &
		    current->interrupts.interrupt_enabled[intid_index] &
		    intid_mask) {
			current->interrupts.enabled_and_pending_count--;
		}
		current->interrupts.interrupt_enabled[intid_index] &=
			~intid_mask;
	}

	sl_unlock(&current->lock);
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

	/*
	 * Find the first enabled and pending interrupt ID, return it, and
	 * deactivate it.
	 */
	sl_lock(&current->lock);
	for (i = 0; i < HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS; ++i) {
		uint32_t enabled_and_pending =
			current->interrupts.interrupt_enabled[i] &
			current->interrupts.interrupt_pending[i];

		if (enabled_and_pending != 0) {
			uint8_t bit_index = ctz(enabled_and_pending);
			/*
			 * Mark it as no longer pending and decrement the count.
			 */
			current->interrupts.interrupt_pending[i] &=
				~(1U << bit_index);
			current->interrupts.enabled_and_pending_count--;
			first_interrupt =
				i * INTERRUPT_REGISTER_BITS + bit_index;
			break;
		}
	}

	sl_unlock(&current->lock);
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

	dlog_info("Injecting IRQ %d for VM %d vCPU %d from VM %d vCPU %d\n",
		  intid, target_vm_id, target_vcpu_idx, current->vm->id,
		  current->cpu->id);
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
		return (struct ffa_value){.func = FFA_NOT_SUPPORTED};
	}

	return (struct ffa_value){
		.func = (FFA_VERSION_MAJOR << FFA_VERSION_MAJOR_OFFSET) |
			FFA_VERSION_MINOR};
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
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	default:
		return ffa_error(FFA_NOT_SUPPORTED);
	}
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

	if ((handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	    FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
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
