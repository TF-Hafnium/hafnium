/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/lifecycle_msg.h"

#include "hf/api.h"
#include "hf/boot_info.h"
#include "hf/call.h"
#include "hf/ffa/interrupts.h"
#include "hf/ffa_internal.h"
#include "hf/live_activation_helper.h"
#include "hf/manifest.h"
#include "hf/partition_pkg.h"
#include "hf/std.h"

static void build_frmk_msg_partition_stop_req(struct vcpu_locked target_locked,
					      bool stop_to_live_activate)
{
	struct vcpu *target_vcpu = target_locked.vcpu;
	uint32_t flags =
		FFA_FRAMEWORK_MSG_BIT | FFA_FRAMEWORK_MSG_PARTITION_STOP_REQ;
	uint32_t reason = stop_to_live_activate ? 1 : 0;

	/*
	 * Build a Framework direct request message requesting the vCPU to stop
	 * in order to perform live activation.
	 */
	struct ffa_value args = {
		/* Direct request message. */
		.func = FFA_MSG_SEND_DIRECT_REQ_32,

		/* Populate sender and receiver endpoint IDs. */
		.arg1 = ((uint64_t)HF_SPMC_VM_ID << 16) | target_vcpu->vm->id,

		/*
		 * Message Flags: Framework message and partition stop request.
		 */
		.arg2 = (uint64_t)flags,

		/* Stop request reason. */
		.arg3 = (uint64_t)reason,

		/* Rest of the arguments MBZ. */
	};

	vcpu_dir_req_set_state(target_locked, false, HF_SPMC_VM_ID, args);

	/*
	 * The SP's vCPU runs in SPMC scheduled mode under FFA_DIR_MSG_REQ
	 * partition runtime model.
	 */
	target_vcpu->scheduling_mode = SPMC_MODE;
	target_vcpu->rt_model = RTM_FFA_DIR_REQ;
	CHECK(vcpu_state_set(target_locked, VCPU_STATE_STOPPING));
}

static void initiate_partition_stop_request(struct vcpu_locked target_locked,
					    struct vcpu **next,
					    bool stop_to_live_activate)
{
	build_frmk_msg_partition_stop_req(target_locked, stop_to_live_activate);

	/*
	 * Mask all interrupts to ensure the target partition is not
	 * interrupted while handling the partition stop request message.
	 */
	ffa_interrupts_mask(target_locked);

	/*
	 * Switch to the target vCPU to give it an opportunity to process
	 * the STOP request.
	 */
	*next = target_locked.vcpu;
}

struct ffa_value lifecycle_msg_activation_start_req(struct ffa_value args,
						    struct vcpu **next)
{
	struct vcpu *target_vcpu;
	struct vcpu_locked target_locked;
	ffa_id_t target_endpoint_id;
	uint64_t live_activation_request_status;
	struct live_activation_tracker_locked tracker_locked;
	struct live_activation_tracker *tracker;
	uintpaddr_t new_instance_base_addr;
	uint64_t new_instance_page_count;
	struct vm *target_vm;

	target_endpoint_id = (ffa_id_t)args.arg3;
	new_instance_base_addr = (uintpaddr_t)args.arg4;
	new_instance_page_count = args.arg5;

	target_vm = vm_find(target_endpoint_id);

	if (!vm_id_is_current_world(target_endpoint_id) || target_vm == NULL) {
		dlog_error("Invalid ID specified for SP live activation\n");
		live_activation_request_status = FFA_INVALID_PARAMETERS;
		goto exit_error;
	}

	if (new_instance_base_addr == 0U ||
	    !is_aligned(new_instance_base_addr, PAGE_SIZE)) {
		dlog_error(
			"Invalid physical address specified for new SP "
			"instance\n");
		live_activation_request_status = FFA_INVALID_PARAMETERS;
		goto exit_error;
	}

	if (new_instance_page_count == 0U) {
		dlog_error(
			"Invalid page count specified for new SP instance\n");
		live_activation_request_status = FFA_INVALID_PARAMETERS;
		goto exit_error;
	}

	/* At least one execution context must not be in NULL state. */
	if (!vm_is_discoverable(target_vm)) {
		dlog_error("Target partition not discoverable\n");
		live_activation_request_status = FFA_INVALID_PARAMETERS;
		goto exit_error;
	}

	if (!target_vm->live_activation_support) {
		dlog_error(
			"Target partition does not support live activation\n");
		live_activation_request_status = FFA_NOT_SUPPORTED;
		goto exit_error;
	}

	if (target_vm->vcpu_count != 1) {
		dlog_error("Live activation not supported for MP SP\n");
		live_activation_request_status = FFA_NOT_SUPPORTED;
		goto exit_error;
	}

	tracker_locked = live_activation_tracker_lock();
	tracker = tracker_locked.tracker;

	assert(tracker != NULL);

	/* For an UP SP, the vCPU index is 0 irrespective of physical CPU. */
	target_vcpu = vm_get_vcpu(target_vm, 0);
	target_locked = vcpu_lock(target_vcpu);

	/*
	 * SPMC has already started live activation of a Secure Partition.
	 */
	if (tracker->in_progress) {
		dlog_error("SPMC busy with Live activation\n");
		live_activation_request_status = FFA_BUSY;
		goto exit_unlock;
	}

	/*
	 * Check if START_REQ is being sent again for activation of a specific
	 * SP. Since live activation is a transactional process, deny the
	 * repeated request.
	 */
	if (target_vm->lfa_progress != LFA_PHASE_RESET) {
		dlog_error("Repeated live activation start request denied\n");
		live_activation_request_status = FFA_DENIED;
		goto exit_unlock;
	}

	/*
	 * If the partition's vCPU is in NULL state, reply with
	 * FFA_INVALID_PARAMETERS error code.
	 * If the partition's vCPU has been ABORTED, reply with ABORTED error
	 * code.
	 * If not in WAITING state, SPMC cannot send a message to SP asking it
	 * to stop. Send a reply with RETRY or DENIED error code.
	 */
	switch (target_vcpu->state) {
	case VCPU_STATE_WAITING:
		live_activation_request_status = FFA_SUCCESSFUL; /* Success */
		initiate_partition_stop_request(target_locked, next, true);

		/*
		 * Make a note of the SPMD EL3 LSP which sent the start request
		 * as well as the target secure partition being live activated.
		 */
		tracker->in_progress = true;
		tracker->partition_id = target_vm->id;
		tracker->initiator_id = ffa_sender(args);
		target_vm->lfa_progress = LFA_PHASE_START;

		/*
		 * Make note of target partition's new instance base address, in
		 * staging area.
		 */
		target_vcpu->vm->new_instance_addr =
			pa_init(new_instance_base_addr);
		target_vcpu->vm->new_instance_size =
			(size_t)new_instance_page_count * PAGE_SIZE;
		break;
	case VCPU_STATE_ABORTED:
		dlog_error("Target partition's vCPU in aborted state\n");
		live_activation_request_status = FFA_ABORTED;
		break;
	case VCPU_STATE_NULL:
		dlog_error("Target partition's vCPU in NULL state\n");
		live_activation_request_status = FFA_INVALID_PARAMETERS;
		break;
	default:
		dlog_error("Target partition's vCPU not available\n");
		if (vcpu_is_available(target_vcpu)) {
			live_activation_request_status = FFA_RETRY;
		} else {
			live_activation_request_status = FFA_DENIED;
		}
		break;
	}

exit_unlock:
	vcpu_unlock(&target_locked);
	live_activation_tracker_unlocked(&tracker_locked);

exit_error:
	return ffa_framework_msg_resp(
		HF_SPMC_VM_ID, ffa_sender(args),
		FFA_FRAMEWORK_MSG_LIVE_ACTIVATION_START_RESP,
		live_activation_request_status, 0, 0);
}

struct ffa_value lifecycle_msg_activation_finish_req(struct ffa_value args,
						     struct vcpu **next)
{
	(void)args;
	(void)next;

	return api_ffa_interrupt_return(0);
}

struct ffa_value lifecycle_msg_partition_stop_resp(
	struct ffa_value args, struct vcpu_locked current_locked,
	struct vcpu **next)
{
	enum ffa_error lifecycle_request_status;
	struct vcpu *current = current_locked.vcpu;
	enum vcpu_state to_state;
	struct ffa_value ffa_ret;
	struct live_activation_tracker_locked tracker_locked;
	struct live_activation_tracker *tracker;
	ffa_id_t initiator_id;

	/*
	 * An SP is expected to send stop response partition message only when
	 * SPMC has sent a stop request, with the goal of live activation. If
	 * the SP sent a direct response in any other scenario, deny it.
	 */
	if (current->vm->lfa_progress != LFA_PHASE_START) {
		return ffa_error(FFA_DENIED);
	}

	lifecycle_request_status = args.arg3;

	tracker_locked = live_activation_tracker_lock();
	tracker = tracker_locked.tracker;

	assert(tracker != NULL);
	assert(tracker->in_progress);
	assert(tracker->partition_id == current->vm->id);

	/*
	 * Make note of initiator ID before potentially resetting the tracker.
	 */
	initiator_id = tracker->initiator_id;

	if (lifecycle_request_status == FFA_SUCCESSFUL) {
		struct vm_locked vm_locked;

		dlog_verbose("SP%#x stopped for purpose of live activation\n",
			     current->vm->id);

		/* Unlock vCPU and lock it after VM. */
		vcpu_unlock(&current_locked);
		vm_locked = vm_lock(current->vm);
		current_locked = vcpu_lock(current);
		CHECK(vcpu_state_set(current_locked, VCPU_STATE_STOPPED));
		vm_set_state(vm_locked, VM_STATE_HALTED);

		vm_unlock(&vm_locked);
	} else {
		dlog_error("SP%#x failed to handle partition stop request\n",
			   current->vm->id);
		to_state = VCPU_STATE_WAITING;

		/* Reset live firmware activation tracker. */
		live_activation_tracker_reset(&tracker_locked);
		current->vm->lfa_progress = LFA_PHASE_RESET;
	}

	/* Restore interrupt priority mask. */
	ffa_interrupts_unmask(current);

	ffa_ret = ffa_framework_msg_resp(
		HF_SPMC_VM_ID, initiator_id,
		FFA_FRAMEWORK_MSG_LIVE_ACTIVATION_START_RESP,
		lifecycle_request_status, 0, 0);

	/* Reset the fields tracking the framework message. */
	vcpu_dir_req_reset_state(current_locked);

	/* Forward the response to SPMD EL3 LSP. */
	*next = api_switch_to_other_world(current_locked, ffa_ret, to_state);
	live_activation_tracker_unlocked(&tracker_locked);

	/* A placeholder return code. */
	return api_ffa_interrupt_return(0);
}
