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

struct ffa_value lifecycle_msg_activation_start_req(struct ffa_value args,
						    struct vcpu **next)
{
	(void)next;
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
	(void)args;
	(void)current_locked;
	(void)next;

	return api_ffa_interrupt_return(0);
}
