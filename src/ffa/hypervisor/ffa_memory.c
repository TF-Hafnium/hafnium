/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/ffa_memory.h"

#include "hf/arch/other_world.h"

#include "hf/ffa/init.h"
#include "hf/ffa_internal.h"
#include "hf/ffa_memory_internal.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "sysregs.h"

enum ffa_memory_handle_allocator ffa_memory_get_handle_allocator(void)
{
	return FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
}

static struct ffa_value ffa_other_world_mem_reclaim(
	ffa_memory_handle_t handle, ffa_memory_region_flags_t flags)
{
	return arch_other_world_call((struct ffa_value){
		.func = FFA_MEM_RECLAIM_32,
		.arg1 = (uint32_t)handle,
		.arg2 = (uint32_t)(handle >> 32),
		.arg3 = flags,
	});
}

/**
 * Check validity of the FF-A memory send function attempt.
 */
bool ffa_memory_is_send_valid(ffa_id_t receiver, ffa_id_t sender,
			      uint32_t share_func, bool multiple_borrower)
{
	/*
	 * Currently memory interfaces are not forwarded from hypervisor to
	 * SPMC. However, in absence of SPMC this function should allow
	 * NS-endpoint to SP memory send in order for trusty tests to work.
	 */

	(void)share_func;
	(void)receiver;
	(void)sender;
	(void)multiple_borrower;

	return true;
}

uint32_t ffa_memory_get_other_world_mode(void)
{
	return 0U;
}

bool ffa_memory_is_mem_perm_get_valid(const struct vcpu *current)
{
	if (!current->vm->el0_partition) {
		dlog_error("FFA_MEM_PERM_GET: VM %#x is not an EL0 partition\n",
			   current->vm->id);
		return false;
	}

	return has_vhe_support();
}

bool ffa_memory_is_mem_perm_set_valid(const struct vcpu *current)
{
	(void)current;
	return has_vhe_support();
}

/** Forwards a memory send message on to the other world. */
static struct ffa_value memory_send_other_world_forward(
	struct vm_locked other_world_locked, uint32_t share_func,
	struct ffa_memory_region *memory_region, uint32_t memory_share_length,
	uint32_t fragment_length)
{
	struct ffa_value ret;

	/* Use its own RX buffer. */
	memcpy_s(other_world_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 memory_region, fragment_length);

	other_world_locked.vm->mailbox.recv_func = share_func;
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_FULL;
	ret = arch_other_world_call((struct ffa_value){
		.func = share_func,
		.arg1 = memory_share_length,
		.arg2 = fragment_length,
	});
	/*
	 * After the call to the other world completes it must have finished
	 * reading its RX buffer, so it is ready for another message.
	 */
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Validates a call to donate, lend or share memory to the other world and then
 * updates the stage-2 page tables. Specifically, check if the message length
 * and number of memory region constituents match, and if the transition is
 * valid for the type of memory sending operation.
 *
 * Assumes that the caller has already found and locked the sender VM and the
 * other world VM, and copied the memory region descriptor from the sender's TX
 * buffer to a freshly allocated page from Hafnium's internal pool. The caller
 * must have also validated that the receiver VM ID is valid.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
static struct ffa_value ffa_memory_other_world_send(
	struct vm_locked from_locked, struct vm_locked to_locked,
	struct ffa_memory_region *memory_region, uint32_t memory_share_length,
	uint32_t fragment_length, uint32_t share_func, struct mpool *page_pool)
{
	ffa_memory_handle_t handle;
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_value reclaim_ret;
	(void)reclaim_ret;

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(from_locked, memory_region,
				       memory_share_length, fragment_length,
				       share_func);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_err;
	}

	share_states = share_states_lock();

	if (fragment_length == memory_share_length) {
		/* No more fragments to come, everything fits in one message. */

		/* Forward memory send message on to other world. */
		ret = memory_send_other_world_forward(
			to_locked, share_func, memory_region,
			memory_share_length, fragment_length);
		if (ret.func != FFA_SUCCESS_32) {
			dlog_verbose(
				"%s: failed to forward memory send message to "
				"other world: %s(%s).\n",
				__func__, ffa_func_name(ret.func),
				ffa_error_name(ffa_error_code(ret)));
			goto out;
		}

		handle = ffa_mem_success_handle(ret);
		share_state = allocate_share_state(share_states, share_func,
						   memory_region,
						   fragment_length, handle);
		if (share_state == NULL) {
			dlog_verbose("%s: failed to allocate share state.\n",
				     __func__);
			ret = ffa_error(FFA_NO_MEMORY);

			reclaim_ret = ffa_other_world_mem_reclaim(handle, 0);
			assert(reclaim_ret.func == FFA_SUCCESS_32);
			goto out;
		}

		ret = ffa_memory_send_complete(from_locked, share_states,
					       share_state, page_pool,
					       &share_state->sender_orig_mode);
		if (ret.func != FFA_SUCCESS_32) {
			dlog_verbose(
				"%s: failed to complete memory send: %s(%s).\n",
				__func__, ffa_func_name(ret.func),
				ffa_error_name(ffa_error_code(ret)));

			reclaim_ret = ffa_other_world_mem_reclaim(handle, 0);
			assert(reclaim_ret.func == FFA_SUCCESS_32);
			goto out;
		}
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	} else {
		/* More fragments remaining, fragmented message. */
		dlog_verbose("%s: more fragments remaining: %d/%d\n", __func__,
			     fragment_length, memory_share_length);

		/*
		 * We need to wait for the rest of the fragments before we can
		 * check whether the transaction is valid and unmap the memory.
		 * Call the other world so it can do its initial validation and
		 * assign a handle, and allocate a share state to keep what we
		 * have so far.
		 */
		ret = memory_send_other_world_forward(
			to_locked, share_func, memory_region,
			memory_share_length, fragment_length);
		if (ret.func != FFA_MEM_FRAG_RX_32) {
			dlog_warning(
				"%s: failed to forward to other world: "
				"%s(%s)\n",
				__func__, ffa_func_name(ret.func),
				ffa_error_name(ffa_error_code(ret)));
			goto out;
		}
		if (ret.arg3 != fragment_length) {
			dlog_warning(
				"%s: got unexpected fragment offset for %s "
				"from other world (expected %d, got %lu)\n",
				__func__, ffa_func_name(FFA_MEM_FRAG_RX_32),
				fragment_length, ret.arg3);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}
		if (ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_warning(
				"%s: got unexpected sender ID for %s from "
				"other world (expected %d, got %d)\n",
				__func__, ffa_func_name(FFA_MEM_FRAG_RX_32),
				from_locked.vm->id, ffa_frag_sender(ret));
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}
		handle = ffa_frag_handle(ret);
		share_state = allocate_share_state(share_states, share_func,
						   memory_region,
						   fragment_length, handle);
		if (share_state == NULL) {
			dlog_verbose("%s: failed to allocate share state.\n",
				     __func__);
			ret = ffa_error(FFA_NO_MEMORY);

			reclaim_ret = ffa_other_world_mem_reclaim(handle, 0);
			assert(reclaim_ret.func == FFA_SUCCESS_32);
			goto out;
		}
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)handle,
			.arg2 = (uint32_t)(handle >> 32),
			.arg3 = fragment_length,
		};
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	}

out:
	share_states_unlock(&share_states);
out_err:
	if (memory_region != NULL) {
		mpool_free(page_pool, memory_region);
	}
	return ret;
}

struct ffa_value ffa_memory_other_world_mem_send(
	struct vm *from, uint32_t share_func,
	struct ffa_memory_region **memory_region, uint32_t length,
	uint32_t fragment_length, struct mpool *page_pool)
{
	struct vm *to;
	struct ffa_value ret;

	to = vm_find(HF_OTHER_WORLD_ID);

	/*
	 * The 'to' VM lock is only needed in the case that it is the
	 * TEE VM.
	 */
	struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

	/* Check if the `to` VM has the mailbox busy. */
	if (vm_is_mailbox_busy(vm_to_from_lock.vm1)) {
		dlog_verbose("The other world VM has a message. %x\n",
			     vm_to_from_lock.vm1.vm->id);
		ret = ffa_error(FFA_BUSY);
	} else {
		ret = ffa_memory_other_world_send(
			vm_to_from_lock.vm2, vm_to_from_lock.vm1,
			*memory_region, length, fragment_length, share_func,
			page_pool);
		/*
		 * ffa_other_world_memory_send takes ownership of the
		 * memory_region, so make sure we don't free it.
		 */
		*memory_region = NULL;
	}

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}

/**
 * Validates that the reclaim transition is allowed for the memory region with
 * the given handle which was previously shared with the SPMC. Tells the
 * SPMC to mark it as reclaimed, and updates the page table of the reclaiming
 * VM.
 *
 * To do this information about the memory region is first fetched from the
 * SPMC.
 */
static struct ffa_value ffa_memory_other_world_reclaim(
	struct vm_locked to_locked, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	struct share_states_locked share_states;
	struct ffa_memory_share_state *share_state;
	struct ffa_memory_region *memory_region;
	struct ffa_value ret;

	dump_share_states();

	share_states = share_states_lock();

	share_state = get_share_state(share_states, handle);
	if (share_state == NULL) {
		dlog_verbose("Unable to find share state for handle %#lx.\n",
			     handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}
	memory_region = share_state->memory_region;

	CHECK(memory_region != NULL);

	if (vm_id_is_current_world(to_locked.vm->id) &&
	    to_locked.vm->id != memory_region->sender) {
		dlog_verbose(
			"VM %#x attempted to reclaim memory handle %#lx "
			"originally sent by VM %#x.\n",
			to_locked.vm->id, handle, memory_region->sender);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (!share_state->sending_complete) {
		dlog_verbose(
			"Memory with handle %#lx not fully sent, can't "
			"reclaim.\n",
			handle);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	for (uint32_t i = 0; i < memory_region->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			ffa_memory_region_get_receiver(memory_region, i);
		struct ffa_memory_region_attributes receiver_permissions;

		CHECK(receiver != NULL);

		receiver_permissions = receiver->receiver_permissions;

		/* Skip the entries that relate to SPs. */
		if (!ffa_is_vm_id(receiver_permissions.receiver)) {
			continue;
		}

		/* Check that all VMs have relinquished. */
		if (share_state->retrieved_fragment_count[i] != 0) {
			dlog_verbose(
				"Tried to reclaim memory handle %#lx "
				"that has not been relinquished by all "
				"borrowers(%x).\n",
				handle, receiver_permissions.receiver);
			ret = ffa_error(FFA_DENIED);
			goto out;
		}
	}

	/*
	 * Call to the SPMC, for it to free the memory state tracking
	 * structures. This can fail if the SPs haven't finished using the
	 * memory.
	 */
	ret = ffa_other_world_mem_reclaim(handle, flags);

	if (ret.func != FFA_SUCCESS_32) {
		dlog_verbose(
			"FFA_MEM_RECLAIM returned an error. Expected "
			"FFA_SUCCESS, got %s (%s)\n",
			ffa_func_name(ret.func), ffa_error_name(ret.arg2));
		goto out;
	}

	/*
	 * Masking the CLEAR flag, as this operation was expected to have been
	 * done by the SPMC.
	 */
	flags &= ~FFA_MEMORY_REGION_FLAG_CLEAR;
	ret = ffa_retrieve_check_update(
		to_locked, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, share_state->sender_orig_mode,
		FFA_MEM_RECLAIM_32, flags & FFA_MEM_RECLAIM_CLEAR, page_pool,
		NULL, false);

	if (ret.func == FFA_SUCCESS_32) {
		share_state_free(share_states, share_state, page_pool);
		dlog_verbose("Freed share state after successful reclaim.\n");
	}

out:
	share_states_unlock(&share_states);
	return ret;
}

struct ffa_value ffa_memory_other_world_mem_reclaim(
	struct vm *to, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t flags, struct mpool *page_pool)
{
	struct ffa_value ret;
	struct vm *from = vm_find(HF_TEE_VM_ID);
	struct two_vm_locked vm_to_from_lock;

	if (!ffa_init_is_tee_enabled()) {
		dlog_verbose("Invalid handle %#lx for FFA_MEM_RECLAIM.\n",
			     handle);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	vm_to_from_lock = vm_lock_both(to, from);

	ret = ffa_memory_other_world_reclaim(vm_to_from_lock.vm1, handle, flags,
					     page_pool);

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}

/**
 * Forwards a memory send continuation message on to the other world.
 */
static struct ffa_value memory_send_continue_other_world_forward(
	struct vm_locked other_world_locked, ffa_id_t sender_vm_id,
	void *fragment, uint32_t fragment_length, ffa_memory_handle_t handle)
{
	struct ffa_value ret;

	memcpy_s(other_world_locked.vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 fragment, fragment_length);

	other_world_locked.vm->mailbox.recv_func = FFA_MEM_FRAG_TX_32;
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_FULL;
	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_MEM_FRAG_TX_32,
				   .arg1 = (uint32_t)handle,
				   .arg2 = (uint32_t)(handle >> 32),
				   .arg3 = fragment_length,
				   .arg4 = (uint64_t)sender_vm_id << 16});

	/*
	 * After the call to the other world completes it must have finished
	 * reading its RX buffer, so it is ready for another message.
	 */
	other_world_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return ret;
}

/**
 * Continues an operation to donate, lend or share memory to the other world VM.
 * If this is the last fragment then checks that the transition is valid for the
 * type of memory sending operation and updates the stage-2 page tables of the
 * sender.
 *
 * Assumes that the caller has already found and locked the sender VM and copied
 * the memory region descriptor from the sender's TX buffer to a freshly
 * allocated page from Hafnium's internal pool.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 */
static struct ffa_value ffa_memory_other_world_send_continue(
	struct vm_locked from_locked, struct vm_locked to_locked,
	void *fragment, uint32_t fragment_length, ffa_memory_handle_t handle,
	struct mpool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct ffa_memory_share_state *share_state;
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;

	ret = ffa_memory_send_continue_validate(share_states, handle,
						&share_state,
						from_locked.vm->id, page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto out_free_fragment;
	}
	memory_region = share_state->memory_region;

	if (!memory_region_receivers_from_other_world(memory_region)) {
		dlog_error(
			"Got SPM-allocated handle for memory send to non-other "
			"world VM. This should never happen, and indicates a "
			"bug.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_free_fragment;
	}

	if (to_locked.vm->mailbox.state != MAILBOX_STATE_EMPTY ||
	    to_locked.vm->mailbox.recv == NULL) {
		/*
		 * If the other_world RX buffer is not available, tell the
		 * sender to retry by returning the current offset again.
		 */
		ret = (struct ffa_value){
			.func = FFA_MEM_FRAG_RX_32,
			.arg1 = (uint32_t)handle,
			.arg2 = (uint32_t)(handle >> 32),
			.arg3 = share_state_next_fragment_offset(share_states,
								 share_state),
		};
		goto out_free_fragment;
	}

	/* Add this fragment. */
	share_state->fragments[share_state->fragment_count] = fragment;
	share_state->fragment_constituent_counts[share_state->fragment_count] =
		fragment_length / sizeof(struct ffa_memory_region_constituent);
	share_state->fragment_count++;

	/* Check whether the memory send operation is now ready to complete. */
	if (share_state_sending_complete(share_states, share_state)) {
		struct mpool local_page_pool;

		/*
		 * Use a local page pool so that we can roll back if necessary.
		 */
		mpool_init_with_fallback(&local_page_pool, page_pool);

		ret = ffa_memory_send_complete(from_locked, share_states,
					       share_state, &local_page_pool,
					       &share_state->sender_orig_mode);

		if (ret.func == FFA_SUCCESS_32) {
			/*
			 * Forward final fragment on to the other_world so that
			 * it can complete the memory sending operation.
			 */
			ret = memory_send_continue_other_world_forward(
				to_locked, from_locked.vm->id, fragment,
				fragment_length, handle);

			if (ret.func != FFA_SUCCESS_32) {
				/*
				 * The error will be passed on to the caller,
				 * but log it here too.
				 */
				dlog_verbose(
					"other_world didn't successfully "
					"complete "
					"memory send operation; returned %#lx "
					"(%lu). Rolling back.\n",
					ret.func, ret.arg2);

				/*
				 * The other_world failed to complete the send
				 * operation, so roll back the page table update
				 * for the VM. This can't fail because it won't
				 * try to allocate more memory than was freed
				 * into the `local_page_pool` by
				 * `ffa_send_check_update` in the initial
				 * update.
				 */
				CHECK(ffa_region_group_identity_map(
					      from_locked,
					      share_state->fragments,
					      share_state
						      ->fragment_constituent_counts,
					      share_state->fragment_count,
					      share_state->sender_orig_mode,
					      &local_page_pool,
					      MAP_ACTION_COMMIT, NULL)
					      .func == FFA_SUCCESS_32);
			}
		} else {
			/* Abort sending to other_world. */
			struct ffa_value other_world_ret =
				ffa_other_world_mem_reclaim(handle, 0);

			if (other_world_ret.func != FFA_SUCCESS_32) {
				/*
				 * Nothing we can do if other_world doesn't
				 * abort properly, just log it.
				 */
				dlog_verbose(
					"other_world didn't successfully abort "
					"failed memory send operation; "
					"returned %#lx %lu).\n",
					other_world_ret.func,
					other_world_ret.arg2);
			}
			/*
			 * We don't need to free the share state in this case
			 * because ffa_memory_send_complete does that already.
			 */
		}

		mpool_fini(&local_page_pool);
	} else {
		uint32_t next_fragment_offset =
			share_state_next_fragment_offset(share_states,
							 share_state);

		ret = memory_send_continue_other_world_forward(
			to_locked, from_locked.vm->id, fragment,
			fragment_length, handle);

		if (ret.func != FFA_MEM_FRAG_RX_32 ||
		    ffa_frag_handle(ret) != handle ||
		    ret.arg3 != next_fragment_offset ||
		    ffa_frag_sender(ret) != from_locked.vm->id) {
			dlog_verbose(
				"Got unexpected result from forwarding "
				"FFA_MEM_FRAG_TX to other_world: %#lx (handle "
				"%#lx, offset %lu, sender %d); expected "
				"FFA_MEM_FRAG_RX (handle %#lx, offset %d, "
				"sender %d).\n",
				ret.func, ffa_frag_handle(ret), ret.arg3,
				ffa_frag_sender(ret), handle,
				next_fragment_offset, from_locked.vm->id);
			/* Free share state. */
			share_state_free(share_states, share_state, page_pool);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		ret = (struct ffa_value){.func = FFA_MEM_FRAG_RX_32,
					 .arg1 = (uint32_t)handle,
					 .arg2 = (uint32_t)(handle >> 32),
					 .arg3 = next_fragment_offset};
	}
	goto out;

out_free_fragment:
	mpool_free(page_pool, fragment);

out:
	share_states_unlock(&share_states);
	return ret;
}

struct ffa_value ffa_memory_other_world_mem_send_continue(
	struct vm *from, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct mpool *page_pool)
{
	struct ffa_value ret;
	struct vm *to = vm_find(HF_TEE_VM_ID);
	struct two_vm_locked vm_to_from_lock = vm_lock_both(to, from);

	/*
	 * The TEE RX buffer state is checked in
	 * `ffa_memory_other_world_send_continue` rather than here, as
	 * we need to return `FFA_MEM_FRAG_RX` with the current offset
	 * rather than FFA_ERROR FFA_BUSY in case it is busy.
	 */

	ret = ffa_memory_other_world_send_continue(
		vm_to_from_lock.vm2, vm_to_from_lock.vm1, fragment,
		fragment_length, handle, page_pool);
	/*
	 * `ffa_memory_other_world_send_continue` takes ownership of the
	 * fragment_copy, so we don't need to free it here.
	 */

	vm_unlock(&vm_to_from_lock.vm1);
	vm_unlock(&vm_to_from_lock.vm2);

	return ret;
}

ffa_memory_attributes_t ffa_memory_add_security_bit_from_mode(
	ffa_memory_attributes_t attributes, uint32_t mode)
{
	(void)mode;

	return attributes;
}
