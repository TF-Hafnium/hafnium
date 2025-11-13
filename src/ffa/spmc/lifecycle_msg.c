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

/* Helper to load, copy, and validate a new SP package for live activation. */
static bool load_and_validate_package(struct mm_stage1_locked stage1_locked,
				      struct manifest_vm *vm_config,
				      paddr_t staging_pa, size_t staging_sz,
				      struct partition_pkg *pkg,
				      struct fdt *manifest_fdt)
{
	size_t max_size = align_up(vm_config->secondary.mem_size, PAGE_SIZE);
	uintptr_t load_addr = vm_config->partition.load_addr;
	size_t image_size;
	void *fdt_ptr;
	size_t fdt_size;
	struct fdt_node root;
	bool pkg_ready = false;
	bool success = false;

	/*
	 * Map the old instance's package area as RW before copying new
	 * instance. It might have been marked as read-only during cold boot.
	 */
	if (mm_identity_map(stage1_locked, pa_init(load_addr),
			    pa_add(pa_init(load_addr), max_size),
			    MM_MODE_R | MM_MODE_W) == NULL) {
		dlog_error("%s: failed to map old instance RW at 0x%lx",
			   __func__, load_addr);
		return false;
	}

	/* Map the staging area as Read only. */
	if (mm_identity_map(stage1_locked, staging_pa,
			    pa_add(staging_pa, staging_sz),
			    MM_MODE_R) == NULL) {
		dlog_error("%s: failed to map staging R at 0x%lx", __func__,
			   pa_addr(staging_pa));

		/*
		 * TODO: Revert back the old instance's package area to its
		 * original mode, need not be READ only.
		 */
		mm_identity_map(stage1_locked, pa_init(load_addr),
				pa_add(pa_init(load_addr), staging_sz),
				MM_MODE_R);
		return false;
	}

	dlog_verbose("Copying instance from staging: addr: 0x%lx size: 0x%zx\n",
		     load_addr, staging_sz);

	/* Copy and zero trailing bytes */
	memcpy_s((void *)load_addr, max_size,
		 ptr_from_va(va_from_pa(staging_pa)), staging_sz);

	if (staging_sz < max_size) {
		memset_s((void *)(load_addr + staging_sz),
			 max_size - staging_sz, 0, max_size - staging_sz);
	}

	/*
	 * When launching an SP, the caches are initially disabled. So the data
	 * must be available without the cache. Flush it to ensure it is
	 * available with caches disabled.
	 */
	arch_mm_flush_dcache((void *)load_addr, max_size);

	/* Unmap the staging area. */
	CHECK(mm_unmap(stage1_locked, staging_pa,
		       pa_add(staging_pa, staging_sz)));

	/* Initialize the partition package */
	if (!partition_pkg_init(stage1_locked, pa_init(load_addr), pkg)) {
		dlog_error("%s: partition_pkg_init failed", __func__);
		goto out;
	}
	pkg_ready = true;

	/* Determine actual image size */
	image_size = align_up(pa_difference(pkg->total.begin, pkg->total.end),
			      PAGE_SIZE);
	if (image_size > staging_sz) {
		dlog_error("%s: image size %zx > staging %zx", __func__,
			   image_size, staging_sz);
		goto out;
	}

	/* Validate partition manifest FDT */
	fdt_ptr = ptr_from_va(va_from_pa(pkg->pm.begin));
	fdt_size = pa_difference(pkg->pm.begin, pkg->pm.end);

	if (!fdt_init_from_ptr(manifest_fdt, fdt_ptr, fdt_size)) {
		dlog_error("%s: invalid FDT", __func__);
		goto out;
	}

	/* Check "compatible" property. */
	if (!fdt_find_node(manifest_fdt, "/", &root) ||
	    (!fdt_is_compatible(&root, "arm,ffa-manifest-1.0") &&
	     !fdt_is_compatible(&root, "arm,ffa-manifest-1.1"))) {
		dlog_error("%s: manifest incompatible", __func__);
		goto out;
	}

	success = true;
out:
	if (!success && pkg_ready) {
		partition_pkg_deinit(stage1_locked, pkg);
	}

	return success;
}

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

static bool check_partition_stop_resp(struct vcpu_locked current_locked,
				      struct ffa_value args)
{
	uintptr_t live_buffer_base_addr = (uintptr_t)args.arg4;
	uint64_t live_buffer_size = args.arg5;
	struct manifest *manager_manifest;
	struct manifest_vm *vm_config;
	struct vm *vm = current_locked.vcpu->vm;
	uintptr_t buffer_addr_from_manifest;
	uint64_t buffer_size_from_manifest;

	manager_manifest = get_hypervisor_manifest();
	vm_config = &(manager_manifest->vm[vm->id - HF_VM_ID_OFFSET]);

	CHECK(vm_config->partition.live_activation.live_state_buffer != NULL);
	buffer_addr_from_manifest = vm_config->partition.live_activation
					    .live_state_buffer->base_address;
	buffer_size_from_manifest = (vm_config->partition.live_activation
					     .live_state_buffer->page_count) *
				    PAGE_SIZE;

	if (live_buffer_base_addr != buffer_addr_from_manifest ||
	    live_buffer_size != buffer_size_from_manifest) {
		dlog_error(
			"Illegal values specified by SP %x for live state "
			"buffer. Base address: %lx Size: %lx\n",
			current_locked.vcpu->vm->id, live_buffer_base_addr,
			live_buffer_size);
		return false;
	}

	return true;
}

/*
 * Check if the new partition package is valid (must comply to a specific
 * format supported by Hafnium project).
 * Copy new instance of the partition to load address, effectively replacing old
 * instance in execution.
 */
static bool prepare_partition_new_instance(struct vm_locked vm_locked)
{
	struct manifest *manager_manifest = get_hypervisor_manifest();
	struct manifest_vm *vm_config =
		&manager_manifest->vm[vm_locked.vm->id - HF_VM_ID_OFFSET];
	struct vm *vm = vm_locked.vm;
	struct mm_stage1_locked stage1_locked = mm_lock_stage1();
	struct partition_pkg pkg;
	struct fdt manifest_fdt;
	bool ret_val = false;
	struct string boot_info_node_name = STRING_INIT("boot-info");
	struct fdt_node root;
	struct fdt_node ffa_node;
	struct fdt_node boot_info_node;

	size_t max_size = align_up(vm_config->secondary.mem_size, PAGE_SIZE);
	size_t new_instance_size = align_up(vm->new_instance_size, PAGE_SIZE);

	if (new_instance_size > max_size) {
		dlog_error(
			"%s: New instance size %zx exceeds MAX allowed size "
			"%zx",
			__func__, new_instance_size, max_size);
		goto out;
	}

	/*
	 * Load, copy, and validate the new partition package.
	 * FF-A requires the new instance manifest to be compatible with the
	 * existing instance manifest. Hafnium currently simplifies this by
	 * requiring the platform integrator to reuse the exact same manifest
	 * for both instances.
	 * TODO: Relax this restriction and validate compatibility instead.
	 */
	ret_val = load_and_validate_package(
		stage1_locked, vm_config, vm->new_instance_addr,
		new_instance_size, &pkg, &manifest_fdt);
	if (!ret_val) {
		goto out;
	}

	/* Process optional boot-info node. */
	if (fdt_find_node(&manifest_fdt, "/", &root)) {
		ffa_node = root;
		vm_config->partition.boot_info =
			fdt_find_child(&ffa_node, &boot_info_node_name);

		/* Partition subscribed to boot information. */
		if (vm_config->partition.boot_info &&
		    vm_config->partition.gp_register_num !=
			    DEFAULT_BOOT_GP_REGISTER) {
			boot_info_node = ffa_node;

			/* Its package should have available space for it. */
			if (pa_addr(pkg.boot_info.begin) == 0) {
				dlog_warning(
					"Partition Package %s missing "
					"boot-info space\n",
					vm_config->debug_name.data);
			} else if (!ffa_boot_info_node(
					   &boot_info_node, &pkg,
					   vm_config->partition.ffa_version)) {
				dlog_error(
					"%s: failed to process boot "
					"information\n",
					__func__);
			}
		}
	}

	/*
	 * Grant the S-EL0 SP access to the memory by mapping the entire region
	 * of memory for the partition as RX. The S-EL0 partition is then
	 * expected to perform its owns relocations and call the FFA_MEM_PERM_*
	 * API's to change permissions on its image layout.
	 */
	if (vm->el0_partition) {
		mm_mode_t map_mode =
			MM_MODE_R | MM_MODE_X | MM_MODE_USER | MM_MODE_NG;

		if (!vm_identity_map(
			    vm_locked, pa_init(vm_config->partition.load_addr),
			    pa_add(pa_init(vm_config->partition.load_addr),
				   max_size),
			    map_mode, NULL)) {
			dlog_error("%s: vm_identity_map RX failed", __func__);
			goto out;
		}
	}

	ret_val = true;
out:
	if (ret_val) {
		partition_pkg_deinit(stage1_locked, &pkg);
	}
	mm_unlock_stage1(&stage1_locked);
	return ret_val;
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

		/*
		 * Make note of args that provide information about SP
		 * live state buffer base address and size. if invalid,
		 * put the SP in aborted state.
		 */
		if (check_partition_stop_resp(current_locked, args) &&
		    prepare_partition_new_instance(vm_locked)) {
			to_state = VCPU_STATE_CREATED;
			vm_set_state(vm_locked, VM_STATE_CREATED);
		} else {
			dlog_error(
				"SP failed live activation. Put in aborted "
				"state\n");
			to_state = VCPU_STATE_ABORTED;
			vm_set_state(vm_locked, VM_STATE_ABORTING);

			/* SPMC sends ABORTED response status code to LSP. */
			lifecycle_request_status = FFA_ABORTED;

			/* Reset live firmware activation tracker. */
			live_activation_tracker_reset(&tracker_locked);
			current->vm->lfa_progress = LFA_PHASE_RESET;
		}

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
