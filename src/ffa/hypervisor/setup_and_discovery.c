/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/setup_and_discovery.h"

#include "hf/arch/other_world.h"
#include "hf/arch/std.h"

#include "hf/check.h"
#include "hf/ffa/init.h"
#include "hf/ffa/vm.h"
#include "hf/ffa_internal.h"
#include "hf/manifest.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "smc.h"

struct ffa_value ffa_setup_spmc_id_get(void)
{
	if (ffa_init_is_tee_enabled()) {
		/*
		 * Fetch the SPMC ID from the SPMD using FFA_SPM_ID_GET.
		 * DEN0077A FF-A v1.1 Beta0 section 13.9.2
		 * "FFA_SPM_ID_GET invocation at a non-secure physical FF-A
		 * instance returns the ID of the SPMC."
		 */
		return smc_ffa_call(
			(struct ffa_value){.func = FFA_SPM_ID_GET_32});
	}

	return (struct ffa_value){
		.func = FFA_ERROR_32,
		.arg2 = FFA_NOT_SUPPORTED,
	};
}

/**
 * Returns FFA_ERROR as FFA_SECONDARY_EP_REGISTER is not supported at the
 * non-secure FF-A instances.
 */
bool ffa_setup_is_secondary_ep_register_supported(void)
{
	return false;
}

void ffa_setup_rxtx_map_spmc(paddr_t recv, paddr_t send, uint64_t page_count)
{
	struct ffa_value ret;

	ret = arch_other_world_call((struct ffa_value){.func = FFA_RXTX_MAP_64,
						       .arg1 = pa_addr(recv),
						       .arg2 = pa_addr(send),
						       .arg3 = page_count});
	CHECK(ret.func == FFA_SUCCESS_32);
}

void ffa_setup_rxtx_map_forward(struct vm_locked vm_locked)
{
	struct vm *vm = vm_locked.vm;
	struct vm *other_world;

	if (!ffa_init_is_tee_enabled()) {
		vm_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;
		return;
	}

	if (!ffa_vm_supports_indirect_messages(vm)) {
		return;
	}

	/* Hypervisor always forward the call to the SPMC. */

	other_world = vm_find(HF_OTHER_WORLD_ID);

	/* Fill the buffers descriptor in SPMC's RX buffer. */
	ffa_endpoint_rx_tx_descriptor_init(
		(struct ffa_endpoint_rx_tx_descriptor *)
			other_world->mailbox.recv,
		vm->id, (uintptr_t)vm->mailbox.recv,
		(uintptr_t)vm->mailbox.send);

	ffa_setup_rxtx_map_spmc(pa_init(0), pa_init(0), 0);

	vm_locked.vm->mailbox.state = MAILBOX_STATE_OTHER_WORLD_OWNED;

	dlog_verbose("Mailbox of %x owned by SPMC.\n", vm_locked.vm->id);
}

void ffa_setup_rxtx_unmap_forward(struct vm_locked vm_locked)
{
	struct ffa_value ret;
	uint64_t func;
	ffa_id_t id;

	assert(vm_locked.vm != NULL);

	id = vm_locked.vm->id;

	if (!ffa_init_is_tee_enabled()) {
		return;
	}

	if (!ffa_vm_supports_indirect_messages(vm_locked.vm)) {
		return;
	}

	/* Hypervisor always forwards forward RXTX_UNMAP to SPMC. */
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RXTX_UNMAP_32,
		.arg1 = (uint64_t)id << FFA_RXTX_ALLOCATOR_SHIFT,
	});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == (uint64_t)SMCCC_ERROR_UNKNOWN) {
		panic("Unknown error forwarding RXTX_UNMAP.\n");
	} else if (func == FFA_ERROR_32) {
		panic("Error %d forwarding RX/TX buffers.\n", ret.arg2);
	} else if (func != FFA_SUCCESS_32) {
		panic("Unexpected function %#x returned forwarding RX/TX "
		      "buffers.",
		      ret.func);
	}
}

bool ffa_setup_partition_info_get_regs_forward_allowed(void)
{
	/*
	 * Allow forwarding from the Hypervisor if TEE or SPMC exists and
	 * declared as such in the Hypervisor manifest.
	 */
	return ffa_init_is_tee_enabled();
}

/*
 * Forward helper for FFA_PARTITION_INFO_GET.
 * Emits FFA_PARTITION_INFO_GET from Hypervisor to SPMC if allowed.
 */
size_t ffa_setup_partition_info_get_forward(
	const struct ffa_uuid *uuid, uint32_t flags,
	struct ffa_partition_info *partitions, const size_t partitions_max_len,
	size_t entries_count)
{
	const struct vm *tee = vm_find(HF_TEE_VM_ID);
	struct ffa_partition_info *tee_partitions;
	size_t tee_partitions_count;
	struct ffa_value ret;
	size_t res;

	CHECK(tee != NULL);
	CHECK(entries_count < MAX_VMS);

	/*
	 * Allow forwarding from the Hypervisor if TEE or SPMC exists and
	 * declared as such in the Hypervisor manifest.
	 */
	if (!ffa_init_is_tee_enabled()) {
		return entries_count;
	}

	ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_PARTITION_INFO_GET_32,
				   .arg1 = uuid->uuid[0],
				   .arg2 = uuid->uuid[1],
				   .arg3 = uuid->uuid[2],
				   .arg4 = uuid->uuid[3],
				   .arg5 = flags});
	if (ffa_func_id(ret) != FFA_SUCCESS_32) {
		dlog_verbose(
			"Failed forwarding FFA_PARTITION_INFO_GET to "
			"the SPMC.\n");
		return entries_count;
	}

	tee_partitions_count = ffa_partition_info_get_count(ret);

	/*
	 * Check that the limit of the buffer can't be surpassed in the checks
	 * below.
	 */
	if (tee_partitions_count == 0 ||
	    add_overflow(tee_partitions_count, entries_count, &res) ||
	    res > partitions_max_len) {
		dlog_verbose(
			"Invalid number of SPs returned by the "
			"SPMC.\n");
		return entries_count;
	}

	if ((flags & FFA_PARTITION_COUNT_FLAG_MASK) ==
	    FFA_PARTITION_COUNT_FLAG) {
		entries_count = res;
	} else {
		tee_partitions = (struct ffa_partition_info *)tee->mailbox.send;
		for (size_t index = 0; index < tee_partitions_count; index++) {
			partitions[entries_count] = tee_partitions[index];
			++entries_count;
		}

		/* Release the RX buffer. */
		ret = arch_other_world_call(
			(struct ffa_value){.func = FFA_RX_RELEASE_32});
		CHECK(ret.func == FFA_SUCCESS_32);
	}

	return entries_count;
}

void ffa_setup_parse_partition_manifest(struct mm_stage1_locked stage1_locked,
					paddr_t fdt_addr,
					size_t fdt_allocated_size,
					const struct manifest_vm *manifest_vm,
					const struct boot_params *boot_params)
{
	struct fdt partition_fdt;

	/*
	 * If the partition is an FF-A partition and is not
	 * hypervisor loaded, the manifest is passed in the
	 * partition package and is parsed during
	 * manifest_init() and secondary fdt should be empty.
	 */
	CHECK(manifest_vm->is_hyp_loaded);
	CHECK(mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, fdt_allocated_size),
			      MM_MODE_R) != NULL);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	CHECK(fdt_init_from_ptr(&partition_fdt, (void *)pa_addr(fdt_addr),
				fdt_allocated_size) == true);
	CHECK(parse_ffa_manifest(&partition_fdt,
				 (struct manifest_vm *)manifest_vm, NULL,
				 boot_params) == MANIFEST_SUCCESS);
	CHECK(mm_unmap(stage1_locked, fdt_addr,
		       pa_add(fdt_addr, fdt_allocated_size)) == true);
}

ffa_partition_properties_t ffa_setup_partition_properties(
	ffa_id_t caller_id, const struct vm *target)
{
	ffa_partition_properties_t result = target->messaging_method;
	/*
	 * VMs support indirect messaging only in the Normal World.
	 * Primary VM cannot receive direct requests.
	 * Secondary VMs cannot send direct requests.
	 */
	if (!vm_id_is_current_world(caller_id)) {
		result &= ~FFA_PARTITION_INDIRECT_MSG;
	}
	if (vm_is_primary(target)) {
		result &= ~FFA_PARTITION_DIRECT_REQ_RECV;
	} else {
		result &= ~FFA_PARTITION_DIRECT_REQ_SEND;
	}
	return result;
}

bool ffa_setup_rx_release_forward(struct vm_locked vm_locked,
				  struct ffa_value *ret)
{
	struct vm *vm = vm_locked.vm;
	ffa_id_t vm_id = vm->id;

	if (!ffa_init_is_tee_enabled() ||
	    !ffa_vm_supports_indirect_messages(vm)) {
		return false;
	}

	CHECK(vm_id_is_current_world(vm_id));

	/* Hypervisor always forward VM's RX_RELEASE to SPMC. */
	*ret = arch_other_world_call(
		(struct ffa_value){.func = FFA_RX_RELEASE_32, .arg1 = vm_id});

	if (ret->func == FFA_SUCCESS_32) {
		/*
		 * The SPMC owns the VM's RX buffer after a successful
		 * FFA_RX_RELEASE call.
		 */
		vm->mailbox.state = MAILBOX_STATE_OTHER_WORLD_OWNED;
	} else {
		dlog_verbose("FFA_RX_RELEASE forwarded failed for VM ID %#x.\n",
			     vm_locked.vm->id);
	}

	return true;
}

/**
 * Acquire the RX buffer of a VM from the SPM.
 *
 * VM RX/TX buffers must have been previously mapped in the SPM either
 * by forwarding VM's RX_TX_MAP API or another way if buffers were
 * declared in manifest.
 *
 * Returns true if the ownership belongs to the hypervisor.
 */
bool ffa_setup_acquire_receiver_rx(struct vm_locked to_locked,
				   struct ffa_value *ret)
{
	struct ffa_value other_world_ret;

	/*
	 * Do not forward the call if either:
	 * - The TEE is not present.
	 * - The VM's version is not FF-A v1.1.
	 * - If the mailbox ownership hasn't been transferred to the SPMC.
	 */
	if (!ffa_init_is_tee_enabled() ||
	    !ffa_vm_supports_indirect_messages(to_locked.vm) ||
	    to_locked.vm->mailbox.state != MAILBOX_STATE_OTHER_WORLD_OWNED) {
		return true;
	}

	other_world_ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RX_ACQUIRE_32, .arg1 = to_locked.vm->id});

	if (ret != NULL) {
		*ret = other_world_ret;
	}

	if (other_world_ret.func == FFA_SUCCESS_32) {
		to_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;
	}

	return other_world_ret.func == FFA_SUCCESS_32;
}

bool ffa_ns_res_info_get_forward(struct vm_locked current_locked,
				 struct ffa_value args, struct ffa_value *ret)
{
	struct vm *vm = current_locked.vm;
	struct vm_locked other_world_locked;

	if (!ffa_is_vm_id(vm->id)) {
		dlog_error("FFA_NS_RES_INFO_GET not supported\n");
		*ret = ffa_error(FFA_NOT_SUPPORTED);
		return true;
	}

	other_world_locked = vm_find_locked(HF_OTHER_WORLD_ID);
	*ret = arch_other_world_call(args);

	/*
	 * Secure World's TX buffer is NWd world RX buffer.
	 * Copy data from there to VM's buffer.
	 */
	memcpy_s(vm->mailbox.recv, FFA_MSG_PAYLOAD_MAX,
		 other_world_locked.vm->mailbox.send, FFA_MSG_PAYLOAD_MAX);

	vm_unlock(&other_world_locked);

	return true;
}
