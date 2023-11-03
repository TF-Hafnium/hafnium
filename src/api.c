/*
 * Copyright 2022 The Hafnium Authors.
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
#include "hf/ffa_v1_0.h"
#include "hf/mm.h"
#include "hf/plat/console.h"
#include "hf/plat/interrupts.h"
#include "hf/spinlock.h"
#include "hf/static_assert.h"
#include "hf/std.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"
#include "vmapi/hf/ffa_v1_0.h"

static_assert(sizeof(struct ffa_partition_info_v1_0) == 8,
	      "Partition information descriptor size doesn't match the one in "
	      "the FF-A 1.0 EAC specification, Table 82.");
static_assert(sizeof(struct ffa_partition_info) == 24,
	      "Partition information descriptor size doesn't match the one in "
	      "the FF-A 1.1 BETA0 EAC specification, Table 13.34.");
static_assert((sizeof(struct ffa_partition_info) & 7) == 0,
	      "Partition information descriptor must be a multiple of 8 bytes"
	      " for ffa_partition_info_get_regs to work correctly. Information"
	      " from this structure are returned in 8 byte registers and the"
	      " count of 8 byte registers is returned by the ABI.");
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

/*
 * Maximum ffa_partition_info entries that can be returned by an invocation
 * of FFA_PARTITION_INFO_GET_REGS_64 is size in bytes, of available
 * registers/args in struct ffa_value divided by size of struct
 * ffa_partition_info. For this ABI, arg3-arg17 in ffa_value can be used, i.e.
 * 15 uint64_t fields. For FF-A v1.1, this value should be 5.
 */
#define MAX_INFO_REGS_ENTRIES_PER_CALL \
	((15 * sizeof(uint64_t)) / sizeof(struct ffa_partition_info))
static_assert(MAX_INFO_REGS_ENTRIES_PER_CALL == 5,
	      "FF-A v1.1 supports no more than 5 entries"
	      " per FFA_PARTITION_INFO_GET_REGS64 calls");

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
struct vcpu *api_ffa_get_vm_vcpu(struct vm *vm, struct vcpu *current)
{
	ffa_vcpu_index_t current_cpu_index = cpu_index(current->cpu);
	struct vcpu *vcpu = NULL;

	CHECK((vm != NULL) && (current != NULL));

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
struct vcpu *api_switch_to_vm(struct vcpu_locked current_locked,
			      struct ffa_value to_ret,
			      enum vcpu_state vcpu_state, ffa_id_t to_id)
{
	struct vm *to_vm = vm_find(to_id);
	struct vcpu *next = api_ffa_get_vm_vcpu(to_vm, current_locked.vcpu);

	CHECK(next != NULL);

	/* Set the return value for the target VM. */
	arch_regs_set_retval(&next->regs, to_ret);

	/* Set the current vCPU state. */
	current_locked.vcpu->state = vcpu_state;

	return next;
}

/**
 * Switches the physical CPU back to the corresponding vCPU of the primary VM.
 *
 * This triggers the scheduling logic to run. Run in the context of secondary VM
 * to cause FFA_RUN to return and the primary VM to regain control of the CPU.
 */
struct vcpu *api_switch_to_primary(struct vcpu_locked current_locked,
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
				primary_ret = (struct ffa_value){
					.func = FFA_INTERRUPT_32};

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

	return api_switch_to_vm(current_locked, primary_ret, secondary_state,
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
struct vcpu *api_switch_to_other_world(struct vcpu_locked current_locked,
				       struct ffa_value other_world_ret,
				       enum vcpu_state vcpu_state)
{
	return api_switch_to_vm(current_locked, other_world_ret, vcpu_state,
				HF_OTHER_WORLD_ID);
}

/**
 * Returns true if the given vCPU is executing in context of an
 * FFA_MSG_SEND_DIRECT_REQ invocation.
 */
bool is_ffa_direct_msg_request_ongoing(struct vcpu_locked locked)
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
	struct vcpu_locked current_locked;
	struct vcpu *next;
	struct ffa_value ret = {
		.func = FFA_INTERRUPT_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	current_locked = vcpu_lock(current);
	next = api_switch_to_primary(current_locked, ret, VCPU_STATE_PREEMPTED);
	vcpu_unlock(&current_locked);

	return next;
}

/**
 * Puts the current vCPU in wait for interrupt mode, and returns to the primary
 * VM.
 */
struct vcpu *api_wait_for_interrupt(struct vcpu *current)
{
	struct vcpu_locked current_locked;
	struct vcpu *next;
	struct ffa_value ret = {
		.func = HF_FFA_RUN_WAIT_FOR_INTERRUPT,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	current_locked = vcpu_lock(current);
	next = api_switch_to_primary(current_locked, ret,
				     VCPU_STATE_BLOCKED_INTERRUPT);
	vcpu_unlock(&current_locked);

	return next;
}

/**
 * Puts the current vCPU in off mode, and returns to the primary VM.
 */
struct vcpu *api_vcpu_off(struct vcpu *current)
{
	struct vcpu_locked current_locked;
	struct vcpu *next;
	struct ffa_value ret = {
		.func = HF_FFA_RUN_WAIT_FOR_INTERRUPT,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
	};

	current_locked = vcpu_lock(current);
	/*
	 * Disable the timer, so the scheduler doesn't get told to call back
	 * based on it.
	 */
	arch_timer_disable_current();

	next = api_switch_to_primary(current_locked, ret, VCPU_STATE_OFF);
	vcpu_unlock(&current_locked);

	return next;
}

/**
 * The current vCPU is blocked on some resource and needs to relinquish
 * control back to the execution context of the endpoint that originally
 * allocated cycles to it.
 */
struct ffa_value api_yield(struct vcpu *current, struct vcpu **next,
			   struct ffa_value *args)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct vcpu_locked current_locked;
	bool transition_allowed;
	enum vcpu_state next_state = VCPU_STATE_RUNNING;
	uint32_t timeout_low = 0;
	uint32_t timeout_high = 0;
	struct vcpu_locked next_locked = (struct vcpu_locked){
		.vcpu = NULL,
	};

	if (args != NULL) {
		if (args->arg4 != 0U || args->arg5 != 0U || args->arg6 != 0U ||
		    args->arg7 != 0U) {
			dlog_error(
				"Parameters passed through registers X4-X7 "
				"must be zero\n");
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
		timeout_low = (uint32_t)args->arg2 & 0xFFFFFFFF;
		timeout_high = (uint32_t)args->arg3 & 0xFFFFFFFF;
	}

	if (current->vm->id == HF_PRIMARY_VM_ID) {
		/* NOOP on the primary as it makes the scheduling decisions. */
		return ret;
	}

	current_locked = vcpu_lock(current);
	transition_allowed = plat_ffa_check_runtime_state_transition(
		current_locked, current->vm->id, HF_INVALID_VM_ID, next_locked,
		FFA_YIELD_32, &next_state);

	if (!transition_allowed) {
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/*
	 * The current vCPU is expected to move to BLOCKED state. However,
	 * under certain circumstances, it is allowed for the current vCPU
	 * to be resumed immediately without ever moving to BLOCKED state. One
	 * such scenario occurs when an SP's execution context attempts to
	 * yield cycles while handling secure interrupt. Refer to the comments
	 * in the SPMC variant of the plat_ffa_yield_prepare function.
	 */
	assert(!vm_id_is_current_world(current->vm->id) ||
	       next_state == VCPU_STATE_BLOCKED);

	ret = plat_ffa_yield_prepare(current_locked, next, timeout_low,
				     timeout_high);
out:
	vcpu_unlock(&current_locked);
	return ret;
}

/**
 * Switches to the primary so that it can switch to the target, or kick it if it
 * is already running on a different physical CPU.
 */
static struct vcpu *api_wake_up_locked(struct vcpu_locked current_locked,
				       struct vcpu *target_vcpu)
{
	struct ffa_value ret = {
		.func = FFA_INTERRUPT_32,
		.arg1 = ffa_vm_vcpu(target_vcpu->vm->id,
				    vcpu_index(target_vcpu)),
	};

	return api_switch_to_primary(current_locked, ret, VCPU_STATE_BLOCKED);
}

struct vcpu *api_wake_up(struct vcpu *current, struct vcpu *target_vcpu)
{
	struct vcpu_locked current_locked;
	struct vcpu *next;

	current_locked = vcpu_lock(current);
	next = api_wake_up_locked(current_locked, target_vcpu);
	vcpu_unlock(&current_locked);

	return next;
}

/**
 * Aborts the vCPU and triggers its VM to abort fully.
 */
struct vcpu *api_abort(struct vcpu *current)
{
	struct ffa_value ret = ffa_error(FFA_ABORTED);
	struct vcpu_locked current_locked;
	struct vcpu *next;
	struct vm_locked vm_locked;

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

	vm_locked = vm_lock(current->vm);
	plat_ffa_free_vm_resources(vm_locked);
	vm_unlock(&vm_locked);

	current_locked = vcpu_lock(current);
	next = api_switch_to_primary(current_locked, ret, VCPU_STATE_ABORTED);
	vcpu_unlock(&current_locked);

	return next;
}

/*
 * Format the partition info descriptors according to the version supported
 * by the endpoint and return the size of the array created.
 */
static struct ffa_value send_versioned_partition_info_descriptors(
	struct vm_locked vm_locked, struct ffa_partition_info *partitions,
	uint32_t vm_count)
{
	struct vm *vm = vm_locked.vm;
	uint32_t version = vm->ffa_version;
	uint32_t partition_info_size;
	uint32_t buffer_size;
	struct ffa_value ret;

	/* Acquire receiver's RX buffer. */
	if (!plat_ffa_acquire_receiver_rx(vm_locked, &ret)) {
		dlog_verbose("Failed to acquire RX buffer for VM %x\n", vm->id);
		return ret;
	}

	if (vm_is_mailbox_busy(vm_locked)) {
		/*
		 * Can't retrieve memory information if the mailbox is not
		 * available.
		 */
		dlog_verbose("RX buffer not ready.\n");
		return ffa_error(FFA_BUSY);
	}

	if (version == MAKE_FFA_VERSION(1, 0)) {
		struct ffa_partition_info_v1_0 *recv_mailbox = vm->mailbox.recv;

		partition_info_size = sizeof(struct ffa_partition_info_v1_0);
		buffer_size = partition_info_size * vm_count;
		if (buffer_size > HF_MAILBOX_SIZE) {
			dlog_error(
				"Partition information does not fit in the "
				"VM's RX "
				"buffer.\n");
			return ffa_error(FFA_NO_MEMORY);
		}

		for (uint32_t i = 0; i < vm_count; i++) {
			/*
			 * Populate the VM's RX buffer with the partition
			 * information. Clear properties bits that must be zero
			 * according to DEN0077A FF-A v1.0 REL Table 8.25.
			 */
			recv_mailbox[i].vm_id = partitions[i].vm_id;
			recv_mailbox[i].vcpu_count = partitions[i].vcpu_count;
			recv_mailbox[i].properties =
				partitions[i].properties &
				~FFA_PARTITION_v1_0_RES_MASK;
		}

	} else {
		partition_info_size = sizeof(struct ffa_partition_info);
		buffer_size = partition_info_size * vm_count;
		if (buffer_size > HF_MAILBOX_SIZE) {
			dlog_error(
				"Partition information does not fit in the "
				"VM's RX "
				"buffer.\n");
			return ffa_error(FFA_NO_MEMORY);
		}

		/* Populate the VM's RX buffer with the partition information.
		 */
		memcpy_s(vm->mailbox.recv, HF_MAILBOX_SIZE, partitions,
			 buffer_size);
	}

	vm->mailbox.recv_size = buffer_size;

	/* Sender is Hypervisor in the normal world (TEE in secure world). */
	vm->mailbox.recv_sender = HF_VM_ID_BASE;
	vm->mailbox.recv_func = FFA_PARTITION_INFO_GET_32;
	vm->mailbox.state = MAILBOX_STATE_FULL;

	/*
	 * Return the count of partition information descriptors in w2
	 * and the size of the descriptors in w3.
	 */
	return (struct ffa_value){.func = FFA_SUCCESS_32,
				  .arg2 = vm_count,
				  .arg3 = partition_info_size};
}

static void api_ffa_fill_partitions_info_array(
	struct ffa_partition_info *partitions, size_t partitions_len,
	const struct ffa_uuid *uuid, bool count_flag, ffa_id_t vm_id,
	ffa_vm_count_t *vm_count_out)
{
	ffa_vm_count_t vm_count = 0;
	bool uuid_is_null = ffa_uuid_is_null(uuid);

	assert(vm_get_count() <= partitions_len);

	/*
	 * Iterate through the VMs to find the ones with a matching
	 * UUID. A Null UUID retrieves information for all VMs.
	 */
	for (ffa_vm_count_t index = 0; index < vm_get_count(); ++index) {
		struct vm *vm = vm_find_index(index);

		if (uuid_is_null || ffa_uuid_equal(uuid, &vm->uuid)) {
			uint16_t array_index = vm_count;

			++vm_count;
			if (count_flag) {
				continue;
			}

			partitions[array_index].vm_id = vm->id;
			partitions[array_index].vcpu_count = vm->vcpu_count;
			partitions[array_index].properties =
				plat_ffa_partition_properties(vm_id, vm);
			partitions[array_index].properties |=
				vm_are_notifications_enabled(vm)
					? FFA_PARTITION_NOTIFICATION
					: 0;
			partitions[array_index].properties |=
				FFA_PARTITION_AARCH64_EXEC;
			if (uuid_is_null) {
				partitions[array_index].uuid = vm->uuid;
			}
		}
	}

	*vm_count_out = vm_count;
}

static inline void api_ffa_pack_vmid_count_props(
	uint64_t *xn, ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count,
	ffa_partition_properties_t properties)
{
	*xn = (uint64_t)vm_id;
	*xn |= (uint64_t)vcpu_count << 16;
	*xn |= (uint64_t)properties << 32;
}

static inline void api_ffa_pack_uuid(uint64_t *xn_1, uint64_t *xn_2,
				     struct ffa_uuid *uuid)
{
	*xn_1 = (uint64_t)uuid->uuid[0];
	*xn_1 |= (uint64_t)uuid->uuid[1] << 32;
	*xn_2 = (uint64_t)uuid->uuid[2];
	*xn_2 |= (uint64_t)uuid->uuid[3] << 32;
}

/**
 * This function forwards the FFA_PARTITION_INFO_GET_REGS ABI to the other world
 * when hafnium is the hypervisor to determine the secure partitions. When
 * hafnium is the SPMC, this function forwards the call to the SPMD to discover
 * SPMD logical partitions. The function returns true when partition information
 * is filled in the partitions array and false if there are errors. Note that
 * the SPMD and SPMC may return an FF-A error code of FFA_NOT_SUPPORTED when
 * there are no SPMD logical partitions or no secure partitions respectively,
 * and this is not considered a failure of the forwarded call. A caller is
 * expected to check the return value before consuming the information in the
 * partitions array passed in and ret_count.
 */
static bool api_ffa_partition_info_get_regs_forward(
	const struct ffa_uuid *uuid, const uint16_t tag,
	struct ffa_partition_info *partitions, uint16_t partitions_len,
	ffa_vm_count_t *ret_count)
{
	(void)tag;
	struct ffa_value ret;
	uint16_t last_index = UINT16_MAX;
	uint16_t curr_index = 0;
	uint16_t start_index = 0;

	if (!plat_ffa_partition_info_get_regs_forward_allowed()) {
		return true;
	}

	while (start_index <= last_index) {
		ret = ffa_partition_info_get_regs(uuid, start_index, 0);
		if (ffa_func_id(ret) != FFA_SUCCESS_64) {
			/*
			 * If there are no logical partitions, SPMD returns
			 * NOT_SUPPORTED, that is not an error. If there are no
			 * secure partitions the SPMC returns NOT_SUPPORTED.
			 */
			if ((ffa_func_id(ret) == FFA_ERROR_32) &&
			    (ffa_error_code(ret) == FFA_NOT_SUPPORTED)) {
				return true;
			}

			return false;
		}

		if (!api_ffa_fill_partition_info_from_regs(
			    ret, start_index, partitions, partitions_len,
			    ret_count)) {
			return false;
		}

		last_index = ffa_partition_info_regs_get_last_idx(ret);
		curr_index = ffa_partition_info_regs_get_curr_idx(ret);
		start_index = curr_index + 1;
	}
	return true;
}

bool api_ffa_fill_partition_info_from_regs(
	struct ffa_value ret, uint16_t start_index,
	struct ffa_partition_info *partitions, uint16_t partitions_len,
	ffa_vm_count_t *ret_count)
{
	uint16_t vm_count = *ret_count;
	uint16_t curr_index = 0;
	uint8_t num_entries = 0;
	uint8_t idx = 0;
	/* List of pointers to args in return value. */
	uint64_t *arg_ptrs[] = {
		&ret.arg3,
		&ret.arg4,
		&ret.arg5,
		&ret.arg6,
		&ret.arg7,
		&ret.extended_val.arg8,
		&ret.extended_val.arg9,
		&ret.extended_val.arg10,
		&ret.extended_val.arg11,
		&ret.extended_val.arg12,
		&ret.extended_val.arg13,
		&ret.extended_val.arg14,
		&ret.extended_val.arg15,
		&ret.extended_val.arg16,
		&ret.extended_val.arg17,
	};

	if (vm_count > partitions_len) {
		return false;
	}

	/*
	 * Tags are currently unused in the implementation. Expect it to be
	 * zero since the implementation does not provide a tag when calling
	 * the FFA_PARTITION_INFO_GET_REGS ABI.
	 */
	assert(ffa_partition_info_regs_get_tag(ret) == 0);

	/*
	 * Hafnium expects the size of the returned descriptor to be equal to
	 * the size of the structure in the FF-A 1.1 specification. When future
	 * enhancements are made, this assert can be relaxed.
	 */
	assert(ffa_partition_info_regs_get_desc_size(ret) ==
	       sizeof(struct ffa_partition_info));

	curr_index = ffa_partition_info_regs_get_curr_idx(ret);

	/* FF-A 1.2 ALP0, section 14.9.2 Usage rule 7. */
	assert(start_index <= curr_index);

	num_entries = curr_index - start_index + 1;
	if (num_entries > (partitions_len - vm_count) ||
	    num_entries > MAX_INFO_REGS_ENTRIES_PER_CALL) {
		return false;
	}

	while (num_entries) {
		uint64_t info = *(arg_ptrs[(ptrdiff_t)(idx++)]);
		uint64_t uuid_lo = *(arg_ptrs[(ptrdiff_t)(idx++)]);
		uint64_t uuid_high = *(arg_ptrs[(ptrdiff_t)(idx++)]);

		partitions[vm_count].vm_id = info & 0xFFFF;
		partitions[vm_count].vcpu_count = (info >> 16) & 0xFFFF;
		partitions[vm_count].properties = (info >> 32);
		partitions[vm_count].uuid.uuid[0] = uuid_lo & 0xFFFFFFFF;
		partitions[vm_count].uuid.uuid[1] =
			(uuid_lo >> 32) & 0xFFFFFFFF;
		partitions[vm_count].uuid.uuid[2] = uuid_high & 0xFFFFFFFF;
		partitions[vm_count].uuid.uuid[3] =
			(uuid_high >> 32) & 0xFFFFFFFF;
		vm_count++;
		num_entries--;
	}

	*ret_count = vm_count;
	return true;
}

struct ffa_value api_ffa_partition_info_get_regs(struct vcpu *current,
						 const struct ffa_uuid *uuid,
						 const uint16_t start_index,
						 const uint16_t tag)
{
	struct vm *current_vm = current->vm;
	static struct ffa_partition_info partitions[2 * MAX_VMS];
	bool uuid_is_null = ffa_uuid_is_null(uuid);
	ffa_vm_count_t vm_count = 0;
	struct ffa_value ret = ffa_error(FFA_INVALID_PARAMETERS);
	uint16_t max_idx = 0;
	uint16_t curr_idx = 0;
	uint8_t num_entries_to_ret = 0;
	uint8_t arg_idx = 3;

	/* list of pointers to args in return value */
	uint64_t *arg_ptrs[] = {
		&(ret).func,
		&(ret).arg1,
		&(ret).arg2,
		&(ret).arg3,
		&(ret).arg4,
		&(ret).arg5,
		&(ret).arg6,
		&(ret).arg7,
		&(ret).extended_val.arg8,
		&(ret).extended_val.arg9,
		&(ret).extended_val.arg10,
		&(ret).extended_val.arg11,
		&(ret).extended_val.arg12,
		&(ret).extended_val.arg13,
		&(ret).extended_val.arg14,
		&(ret).extended_val.arg15,
		&(ret).extended_val.arg16,
		&(ret).extended_val.arg17,
	};

	/* TODO: Add support for using tags */
	if (tag != 0) {
		dlog_error("Tag not 0. Unsupported tag. %d\n", tag);
		return ffa_error(FFA_RETRY);
	}

	memset_s(&partitions, sizeof(partitions), 0, sizeof(partitions));

	api_ffa_fill_partitions_info_array(partitions, ARRAY_SIZE(partitions),
					   uuid, false, current_vm->id,
					   &vm_count);

	/* If UUID is Null vm_count must not be zero at this stage. */
	CHECK(!uuid_is_null || vm_count != 0);

	/*
	 * When running the Hypervisor:
	 * - If UUID is Null the Hypervisor forwards the query to the SPMC for
	 * it to fill with secure partitions information.
	 * When running the SPMC, the SPMC forwards the call to the SPMD to
	 * discover any EL3 SPMD logical partitions, if the call came from an
	 * SP. Otherwise, the call is not forwarded.
	 * TODO: Note that for this ABI, forwarding on every invocation when
	 * uuid is Null is inefficient,and if performance becomes a problem,
	 * this would be a good place to optimize using strategies such as
	 * caching info etc. For now, assuming this inefficiency is not a major
	 * issue.
	 * - If UUID is non-Null vm_count may be zero because the UUID matches
	 * a secure partition and the query is forwarded to the SPMC.
	 * When running the SPMC:
	 * - If UUID is non-Null and vm_count is zero it means there is no such
	 * partition identified in the system.
	 */
	if (vm_id_is_current_world(current_vm->id)) {
		if (!api_ffa_partition_info_get_regs_forward(
			    uuid, tag, partitions, ARRAY_SIZE(partitions),
			    &vm_count)) {
			dlog_error(
				"Failed to forward "
				"ffa_partition_info_get_regs.\n");
			return ffa_error(FFA_DENIED);
		}
	}

	/*
	 * Unrecognized UUID: does not match any of the VMs (or SPs)
	 * and is not Null.
	 */
	if (vm_count == 0 || vm_count > ARRAY_SIZE(partitions)) {
		dlog_verbose(
			"Invalid parameters. vm_count = %d (must not be zero "
			"or > %d)\n",
			vm_count, ARRAY_SIZE(partitions));
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (start_index >= vm_count) {
		dlog_error(
			"start index = %d vm_count = %d (start_index must be "
			"less than vm_count)\n",
			start_index, vm_count);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	max_idx = vm_count - 1;
	num_entries_to_ret = (max_idx - start_index) + 1;
	num_entries_to_ret =
		MIN(num_entries_to_ret, MAX_INFO_REGS_ENTRIES_PER_CALL);
	curr_idx = start_index + num_entries_to_ret - 1;
	assert(curr_idx <= max_idx);

	ret.func = FFA_SUCCESS_64;
	ret.arg2 = (sizeof(struct ffa_partition_info) & 0xFFFF) << 48;
	ret.arg2 |= curr_idx << 16;
	ret.arg2 |= max_idx;

	if (num_entries_to_ret > 1) {
		ret.extended_val.valid = 1;
	}

	for (uint16_t idx = start_index; idx <= curr_idx; ++idx) {
		uint64_t *xn_0 = arg_ptrs[arg_idx++];
		uint64_t *xn_1 = arg_ptrs[arg_idx++];
		uint64_t *xn_2 = arg_ptrs[arg_idx++];

		api_ffa_pack_vmid_count_props(xn_0, partitions[idx].vm_id,
					      partitions[idx].vcpu_count,
					      partitions[idx].properties);
		if (uuid_is_null) {
			api_ffa_pack_uuid(xn_1, xn_2, &partitions[idx].uuid);
		}
		assert(arg_idx <= ARRAY_SIZE(arg_ptrs));
	}

	return ret;
}

struct ffa_value api_ffa_partition_info_get(struct vcpu *current,
					    const struct ffa_uuid *uuid,
					    const uint32_t flags)
{
	struct vm *current_vm = current->vm;
	ffa_vm_count_t vm_count = 0;
	bool count_flag = (flags & FFA_PARTITION_COUNT_FLAG_MASK) ==
			  FFA_PARTITION_COUNT_FLAG;
	bool uuid_is_null = ffa_uuid_is_null(uuid);
	struct ffa_partition_info partitions[2 * MAX_VMS] = {0};
	struct vm_locked vm_locked;
	struct ffa_value ret;

	/* Bits 31:1 Must Be Zero */
	if ((flags & ~FFA_PARTITION_COUNT_FLAG_MASK) != 0) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * No need to count if we are returning the number of partitions as we
	 * already know this.
	 */
	if (uuid_is_null && count_flag) {
		vm_count = vm_get_count();
	} else {
		api_ffa_fill_partitions_info_array(
			partitions, ARRAY_SIZE(partitions), uuid, count_flag,
			current_vm->id, &vm_count);
	}

	/* If UUID is Null vm_count must not be zero at this stage. */
	CHECK(!uuid_is_null || vm_count != 0);

	/*
	 * When running the Hypervisor:
	 * - If UUID is Null the Hypervisor forwards the query to the SPMC for
	 * it to fill with secure partitions information.
	 * - If UUID is non-Null vm_count may be zero because the UUID matches
	 * a secure partition and the query is forwarded to the SPMC.
	 * When running the SPMC:
	 * - If UUID is non-Null and vm_count is zero it means there is no such
	 * partition identified in the system.
	 */
	plat_ffa_partition_info_get_forward(uuid, flags, partitions, &vm_count);

	/*
	 * Unrecognized UUID: does not match any of the VMs (or SPs)
	 * and is not Null.
	 */
	if (vm_count == 0) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * If the count flag is set we don't need to return the partition info
	 * descriptors.
	 */
	if (count_flag) {
		return (struct ffa_value){.func = FFA_SUCCESS_32,
					  .arg2 = vm_count};
	}

	vm_locked = vm_lock(current_vm);
	ret = send_versioned_partition_info_descriptors(vm_locked, partitions,
							vm_count);
	vm_unlock(&vm_locked);
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
 * Returns the SPMC FF-A ID at NS virtual/physical and secure virtual
 * FF-A instances.
 * DEN0077A FF-A v1.1 Beta0 section 13.9 FFA_SPM_ID_GET.
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
				    uint32_t intid,
				    struct vcpu_locked current_locked,
				    struct vcpu **next)
{
	struct vcpu *target_vcpu = target_locked.vcpu;
	struct vcpu *current = current_locked.vcpu;
	struct interrupts *interrupts = &target_vcpu->interrupts;
	int64_t ret = 0;

	/*
	 * We only need to change state and (maybe) trigger a virtual interrupt
	 * if it is enabled and was not previously pending. Otherwise we can
	 * skip everything except setting the pending bit.
	 */
	if (!(vcpu_is_virt_interrupt_enabled(interrupts, intid) &&
	      !vcpu_is_virt_interrupt_pending(interrupts, intid))) {
		goto out;
	}

	/* Increment the count. */
	vcpu_interrupt_count_increment(target_locked, interrupts, intid);

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
		*next = api_wake_up_locked(current_locked, target_vcpu);
	}

out:
	/* Either way, make it pending. */
	vcpu_virt_interrupt_set_pending(interrupts, intid);

	return ret;
}

/**
 * Constructs the return value from a successful FFA_MSG_WAIT call, when used
 * with FFA_MSG_SEND_32.
 */
struct ffa_value ffa_msg_recv_return(const struct vm *receiver)
{
	switch (receiver->mailbox.recv_func) {
	case FFA_MSG_SEND_32:
		return (struct ffa_value){
			.func = FFA_MSG_SEND_32,
			.arg1 = (receiver->mailbox.recv_sender << 16) |
				receiver->id,
			.arg3 = receiver->mailbox.recv_size};
	case FFA_MSG_SEND2_32:
		return (struct ffa_value){
			.func = FFA_RUN_32,
			/*
			 * TODO: FFA_RUN should return vCPU and VM ID in arg1.
			 * Retrieving vCPU requires a rework of the function,
			 * while receiver ID must be set because it's checked by
			 * other APIs (eg: FFA_NOTIFICATION_GET).
			 */
			.arg1 = receiver->id};
	default:
		/* This should never be reached, but return an error in case. */
		dlog_error("Tried to return an invalid message function %#x\n",
			   receiver->mailbox.recv_func);
		return ffa_error(FFA_DENIED);
	}
}

/**
 * Change the state of mailbox to empty, such that the ownership is given to the
 * Partition manager.
 * Returns true if the mailbox was reset successfully, false otherwise.
 */
static bool api_release_mailbox(struct vm_locked vm_locked, int32_t *error_code)
{
	ffa_id_t vm_id = vm_locked.vm->id;
	int32_t error_code_to_ret = 0;

	switch (vm_locked.vm->mailbox.state) {
	case MAILBOX_STATE_EMPTY:
		dlog_verbose("Mailbox of %x is empty.\n", vm_id);
		error_code_to_ret = FFA_DENIED;
		break;
	case MAILBOX_STATE_FULL:
		/* Check it doesn't have pending RX full notifications. */
		if (vm_are_fwk_notifications_pending(vm_locked)) {
			dlog_verbose(
				"Mailbox of endpoint %x has pending "
				"messages.\n",
				vm_id);
			error_code_to_ret = FFA_DENIED;
		}
		break;
	case MAILBOX_STATE_OTHER_WORLD_OWNED:
		/*
		 * The SPMC shouldn't let SP's mailbox get into this state.
		 * For the Hypervisor, the VM may call FFA_RX_RELEASE, whilst
		 * the mailbox is in this state. In that case, we should report
		 * error.
		 */
		if (vm_id_is_current_world(vm_id)) {
			dlog_verbose(
				"Mailbox of endpoint %x in a wrongful state.\n",
				vm_id);
			error_code_to_ret = FFA_ABORTED;
		}
		break;
	}

	if (error_code_to_ret != 0) {
		if (error_code != NULL) {
			*error_code = error_code_to_ret;
		}
		return false;
	}

	vm_locked.vm->mailbox.state = MAILBOX_STATE_EMPTY;

	return true;
}

struct ffa_value api_ffa_msg_wait(struct vcpu *current, struct vcpu **next,
				  struct ffa_value *args)
{
	struct vcpu_locked current_locked;
	enum vcpu_state next_state = VCPU_STATE_RUNNING;
	struct ffa_value ret;
	struct vcpu_locked next_locked = (struct vcpu_locked){
		.vcpu = NULL,
	};

	if (args->arg1 != 0U || args->arg2 != 0U || args->arg3 != 0U ||
	    args->arg4 != 0U || args->arg5 != 0U || args->arg6 != 0U ||
	    args->arg7 != 0U) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	current_locked = vcpu_lock(current);
	if (!plat_ffa_check_runtime_state_transition(
		    current_locked, current->vm->id, HF_INVALID_VM_ID,
		    next_locked, FFA_MSG_WAIT_32, &next_state)) {
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	assert(!vm_id_is_current_world(current->vm->id) ||
	       next_state == VCPU_STATE_WAITING);

	ret = plat_ffa_msg_wait_prepare(current_locked, next);
out:
	vcpu_unlock(&current_locked);

	if (ret.func != FFA_ERROR_32) {
		struct vm_locked vm_locked = vm_lock(current->vm);

		api_release_mailbox(vm_locked, NULL);
		vm_unlock(&vm_locked);
	}

	return ret;
}

/**
 * Prepares the vCPU to run by updating its state and fetching whether a return
 * value needs to be forced onto the vCPU.
 */
static bool api_vcpu_prepare_run(struct vcpu_locked current_locked,
				 struct vcpu_locked vcpu_next_locked,
				 struct ffa_value *run_ret)
{
	struct vm_locked vm_locked;
	bool ret;
	uint64_t timer_remaining_ns = FFA_SLEEP_INDEFINITE;
	bool vcpu_was_init_state = false;
	bool need_vm_lock;
	struct two_vcpu_locked vcpus_locked;

	/*
	 * Check that the registers are available so that the vCPU can be run.
	 *
	 * The VM lock is not needed in the common case so it must only be taken
	 * when it is going to be needed. This ensures there are no inter-vCPU
	 * dependencies in the common run case meaning the sensitive context
	 * switch performance is consistent.
	 */
	struct vcpu *vcpu = vcpu_next_locked.vcpu;
	struct vcpu *current = current_locked.vcpu;

	/* The VM needs to be locked to deliver mailbox messages. */
	need_vm_lock = vcpu->state == VCPU_STATE_WAITING ||
		       (!vcpu->vm->el0_partition &&
			(vcpu->state == VCPU_STATE_BLOCKED_INTERRUPT ||
			 vcpu->state == VCPU_STATE_BLOCKED ||
			 vcpu->state == VCPU_STATE_PREEMPTED));

	if (need_vm_lock) {
		vcpu_unlock(&vcpu_next_locked);
		vcpu_unlock(&current_locked);
		vm_locked = vm_lock(vcpu->vm);

		/* Lock both vCPUs at once to avoid deadlock. */
		vcpus_locked = vcpu_lock_both(current, vcpu);
		current_locked = vcpus_locked.vcpu1;
		vcpu_next_locked = vcpus_locked.vcpu2;
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
			dlog_verbose("VM %#x was aborted, cannot run vCPU %u\n",
				     vcpu->vm->id, vcpu_index(vcpu));
			vcpu->state = VCPU_STATE_ABORTED;
		}
		*run_ret = ffa_error(FFA_ABORTED);
		ret = false;
		goto out;
	}

	switch (vcpu->state) {
	case VCPU_STATE_RUNNING:
	case VCPU_STATE_OFF:
	case VCPU_STATE_ABORTED:
		ret = false;
		goto out;

	case VCPU_STATE_WAITING:
		/*
		 * An initial FFA_RUN is necessary for SP's secondary vCPUs to
		 * reach the message wait loop.
		 */
		if (vcpu->rt_model == RTM_SP_INIT) {
			/*
			 * TODO: this should be removed, but omitting it makes
			 * normal world arch gicv3 tests failing.
			 */
			vcpu->rt_model = RTM_NONE;

			vcpu_was_init_state = true;
			break;
		}

		assert(need_vm_lock == true);
		if (!vm_locked.vm->el0_partition &&
		    plat_ffa_inject_notification_pending_interrupt(
			    vcpu_next_locked, current_locked, vm_locked)) {
			/* TODO: setting a return value to override
			 * the placeholder (FFA_ERROR(INTERRUPTED))
			 * set by FFA_MSG_WAIT. FF-A v1.1 allows
			 * FFA_MSG_WAIT to successfully return even if
			 * it didn't receive a message. TFTF tests are
			 * still expecting an FFA_ERROR instead,
			 * should be fixed?
			 */
			arch_regs_set_retval(
				&vcpu->regs,
				(struct ffa_value){.func = FFA_RUN_32,
						   // TODO: does it make sense
						   // to set vCPU/receiver?
						   .arg1 = 0});
			break;
		}

		/*
		 * A pending message allows the vCPU to run so the message can
		 * be delivered directly.
		 */
		if (vcpu->vm->mailbox.state == MAILBOX_STATE_FULL) {
			arch_regs_set_retval(&vcpu->regs,
					     ffa_msg_recv_return(vcpu->vm));
			break;
		}

		if (vcpu_interrupt_count_get(vcpu_next_locked) > 0) {
			break;
		}

		if (arch_timer_enabled(&vcpu->regs)) {
			timer_remaining_ns =
				arch_timer_remaining_ns(&vcpu->regs);
			if (timer_remaining_ns == 0) {
				break;
			}
		} else {
			dlog_verbose("Timer disabled\n");
		}
		run_ret->func = FFA_MSG_WAIT_32;
		run_ret->arg1 = ffa_vm_vcpu(vcpu->vm->id, vcpu_index(vcpu));
		run_ret->arg2 = timer_remaining_ns;
		ret = false;
		goto out;
	case VCPU_STATE_BLOCKED_INTERRUPT:
		if (need_vm_lock &&
		    plat_ffa_inject_notification_pending_interrupt(
			    vcpu_next_locked, current_locked, vm_locked)) {
			assert(vcpu_interrupt_count_get(vcpu_next_locked) > 0);
			break;
		}

		/* Allow virtual interrupts to be delivered. */
		if (vcpu_interrupt_count_get(vcpu_next_locked) > 0) {
			break;
		}

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
		run_ret->func = HF_FFA_RUN_WAIT_FOR_INTERRUPT;
		run_ret->arg1 = ffa_vm_vcpu(vcpu->vm->id, vcpu_index(vcpu));
		run_ret->arg2 = timer_remaining_ns;

		ret = false;
		goto out;

	case VCPU_STATE_BLOCKED:
		/* A blocked vCPU is run unconditionally. Fall through. */
	case VCPU_STATE_PREEMPTED:
		/* Check NPI is to be injected here. */
		if (need_vm_lock) {
			plat_ffa_inject_notification_pending_interrupt(
				vcpu_next_locked, current_locked, vm_locked);
		}
		break;
	default:
		/*
		 * Execution not expected to reach here. Deny the request
		 * gracefully.
		 */
		*run_ret = ffa_error(FFA_DENIED);
		ret = false;
		goto out;
	}

	plat_ffa_init_schedule_mode_ffa_run(current_locked, vcpu_next_locked);

	/* It has been decided that the vCPU should be run. */
	vcpu->cpu = current_locked.vcpu->cpu;
	vcpu->state = VCPU_STATE_RUNNING;

	if (vcpu_was_init_state) {
		vcpu_set_phys_core_idx(vcpu);
		vcpu_set_boot_info_gp_reg(vcpu);
	}

	/*
	 * Mark the registers as unavailable now that we're about to reflect
	 * them onto the real registers. This will also prevent another physical
	 * CPU from trying to read these registers.
	 */
	vcpu->regs_available = false;

	ret = true;

out:
	if (need_vm_lock) {
		vm_unlock(&vm_locked);
	}
	return ret;
}

struct ffa_value api_ffa_run(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			     struct vcpu *current, struct vcpu **next)
{
	struct vm *vm;
	struct vcpu *vcpu;
	struct ffa_value ret = ffa_error(FFA_INVALID_PARAMETERS);
	enum vcpu_state next_state = VCPU_STATE_RUNNING;
	struct vcpu_locked current_locked;
	struct vcpu_locked vcpu_next_locked;
	struct two_vcpu_locked vcpus_locked;

	current_locked = vcpu_lock(current);
	if (!plat_ffa_run_checks(current_locked, vm_id, vcpu_idx, &ret, next)) {
		goto out;
	}

	if (plat_ffa_run_forward(vm_id, vcpu_idx, &ret)) {
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

	/*
	 * Refer Figure 8.13 Scenario 1 of the FF-A v1.1 EAC spec. SPMC
	 * bypasses the intermediate execution contexts and resumes the
	 * SP execution context that was originally preempted.
	 */
	if (*next != NULL) {
		vcpu = *next;
	} else {
		vcpu = vm_get_vcpu(vm, vcpu_idx);
	}

	/*
	 * Unlock current vCPU to allow it to be locked together with next
	 * vcpu.
	 */
	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, vcpu);
	current_locked = vcpus_locked.vcpu1;
	vcpu_next_locked = vcpus_locked.vcpu2;

	if (!plat_ffa_check_runtime_state_transition(
		    current_locked, current->vm->id, HF_INVALID_VM_ID,
		    vcpu_next_locked, FFA_RUN_32, &next_state)) {
		ret = ffa_error(FFA_DENIED);
		goto out_vcpu;
	}

	if (!api_vcpu_prepare_run(current_locked, vcpu_next_locked, &ret)) {
		goto out_vcpu;
	}

	/*
	 * Inject timer interrupt if timer has expired. It's safe to access
	 * vcpu->regs here because api_vcpu_prepare_run already made sure that
	 * regs_available was true (and then set it to false) before returning
	 * true.
	 */
	if (arch_timer_pending(&vcpu->regs)) {
		/* Make virtual timer interrupt pending. */
		api_interrupt_inject_locked(vcpu_next_locked,
					    HF_VIRTUAL_TIMER_INTID,
					    vcpu_next_locked, NULL);

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

	assert(!vm_id_is_current_world(current->vm->id) ||
	       next_state == VCPU_STATE_BLOCKED);
	current->state = VCPU_STATE_BLOCKED;

	/*
	 * Set a placeholder return code to the scheduler. This will be
	 * overwritten when the switch back to the primary occurs.
	 */
	ret.func = FFA_INTERRUPT_32;
	ret.arg1 = 0;
	ret.arg2 = 0;

out_vcpu:
	vcpu_unlock(&vcpu_next_locked);

out:
	vcpu_unlock(&current_locked);
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
	uint32_t orig_send_mode = 0;
	uint32_t orig_recv_mode = 0;
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

	/* Set stage 2 translation tables only for virtual FF-A instances. */
	if (vm_id_is_current_world(vm_locked.vm->id)) {
		/*
		 * Ensure the pages are valid, owned and exclusive to the VM and
		 * that the VM has the required access to the memory.
		 */
		if (!vm_mem_get_mode(vm_locked, send, ipa_add(send, PAGE_SIZE),
				     &orig_send_mode) ||
		    !api_mode_valid_owned_and_exclusive(orig_send_mode) ||
		    (orig_send_mode & MM_MODE_R) == 0 ||
		    (orig_send_mode & MM_MODE_W) == 0) {
			dlog_error(
				"VM doesn't have required access rights to map "
				"TX buffer in stage 2.\n");
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		if (!vm_mem_get_mode(vm_locked, recv, ipa_add(recv, PAGE_SIZE),
				     &orig_recv_mode) ||
		    !api_mode_valid_owned_and_exclusive(orig_recv_mode) ||
		    (orig_recv_mode & MM_MODE_R) == 0) {
			dlog_error(
				"VM doesn't have required access rights to map "
				"RX buffer in stage 2.\n");
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		/* Take memory ownership away from the VM and mark as shared. */
		uint32_t mode = MM_MODE_UNOWNED | MM_MODE_SHARED | MM_MODE_R |
				MM_MODE_W;
		if (vm_locked.vm->el0_partition) {
			mode |= MM_MODE_USER | MM_MODE_NG;
		}

		if (!vm_identity_map(vm_locked, pa_send_begin, pa_send_end,
				     mode, local_page_pool, NULL)) {
			dlog_error(
				"Cannot allocate a new entry in stage 2 "
				"translation table.\n");
			ret = ffa_error(FFA_NO_MEMORY);
			goto out;
		}

		mode = MM_MODE_UNOWNED | MM_MODE_SHARED | MM_MODE_R;
		if (vm_locked.vm->el0_partition) {
			mode |= MM_MODE_USER | MM_MODE_NG;
		}

		if (!vm_identity_map(vm_locked, pa_recv_begin, pa_recv_end,
				     mode, local_page_pool, NULL)) {
			/* TODO: partial defrag of failed range. */
			/* Recover any memory consumed in failed mapping. */
			vm_ptable_defrag(vm_locked, local_page_pool);
			goto fail_undo_send;
		}
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
			      orig_recv_mode, local_page_pool, NULL));

fail_undo_send:
	CHECK(vm_identity_map(vm_locked, pa_send_begin, pa_send_end,
			      orig_send_mode, local_page_pool, NULL));
	ret = ffa_error(FFA_NO_MEMORY);

out:
	return ret;
}

static void api_get_rxtx_description(struct vm *current_vm, ipaddr_t *send,
				     ipaddr_t *recv, uint32_t *page_count,
				     ffa_id_t *owner_vm_id)
{
	/*
	 * If the message has been forwarded the effective addresses are in
	 * hypervisor's TX buffer.
	 */
	bool forwarded = (current_vm->id == HF_OTHER_WORLD_ID) &&
			 (ipa_addr(*send) == 0) && (ipa_addr(*recv) == 0) &&
			 (*page_count == 0);

	if (forwarded) {
		struct vm_locked vm_locked = vm_lock(current_vm);
		struct ffa_endpoint_rx_tx_descriptor *endpoint_desc =
			(struct ffa_endpoint_rx_tx_descriptor *)
				vm_locked.vm->mailbox.send;
		struct ffa_composite_memory_region *rx_region =
			ffa_enpoint_get_rx_memory_region(endpoint_desc);
		struct ffa_composite_memory_region *tx_region =
			ffa_enpoint_get_tx_memory_region(endpoint_desc);

		*owner_vm_id = endpoint_desc->endpoint_id;
		*recv = ipa_init(rx_region->constituents[0].address);
		*send = ipa_init(tx_region->constituents[0].address);
		*page_count = rx_region->constituents[0].page_count;

		vm_unlock(&vm_locked);
	} else {
		*owner_vm_id = current_vm->id;
	}
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
 */
struct ffa_value api_ffa_rxtx_map(ipaddr_t send, ipaddr_t recv,
				  uint32_t page_count, struct vcpu *current)
{
	struct ffa_value ret;
	struct vm_locked owner_vm_locked;
	struct mm_stage1_locked mm_stage1_locked;
	struct mpool local_page_pool;
	ffa_id_t owner_vm_id;

	/*
	 * Get the original buffer addresses and VM ID in case of forwarded
	 * message.
	 */
	api_get_rxtx_description(current->vm, &send, &recv, &page_count,
				 &owner_vm_id);

	owner_vm_locked = plat_ffa_vm_find_locked_create(owner_vm_id);
	if (owner_vm_locked.vm == NULL) {
		dlog_error("Cannot map RX/TX for VM ID %#x, not found.\n",
			   owner_vm_id);
		return ffa_error(FFA_DENIED);
	}

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if any
	 * stage of the process fails.
	 */
	mpool_init_with_fallback(&local_page_pool, &api_page_pool);

	mm_stage1_locked = mm_lock_stage1();

	ret = api_vm_configure_pages(mm_stage1_locked, owner_vm_locked, send,
				     recv, page_count, &local_page_pool);
	if (ret.func != FFA_SUCCESS_32) {
		goto exit;
	}

	/* Forward buffer mapping to SPMC if coming from a VM. */
	plat_ffa_rxtx_map_forward(owner_vm_locked);

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

exit:
	mpool_fini(&local_page_pool);
	mm_unlock_stage1(&mm_stage1_locked);
	vm_unlock(&owner_vm_locked);

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
struct ffa_value api_ffa_rxtx_unmap(ffa_id_t allocator_id, struct vcpu *current)
{
	struct vm *vm = current->vm;
	struct vm_locked vm_locked;
	ffa_id_t owner_vm_id;
	struct mm_stage1_locked mm_stage1_locked;
	paddr_t send_pa_begin;
	paddr_t send_pa_end;
	paddr_t recv_pa_begin;
	paddr_t recv_pa_end;
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};

	if (vm->id == HF_HYPERVISOR_VM_ID && !ffa_is_vm_id(allocator_id)) {
		dlog_error(
			"The Hypervisor must specify a valid VM ID in register "
			"W1, if FFA_RXTX_UNMAP call forwarded to SPM.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Ensure `allocator_id` is set only at Non-Secure Physical instance. */
	if (vm_id_is_current_world(vm->id) && (allocator_id != 0)) {
		dlog_error(
			"The register W1 (containing ID) must be 0 at virtual "
			"instances.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* VM ID of which buffers have to be unmapped. */
	owner_vm_id = (allocator_id != 0) ? allocator_id : vm->id;

	vm_locked = plat_ffa_vm_find_locked(owner_vm_id);
	vm = vm_locked.vm;
	if (vm == NULL) {
		dlog_error("Cannot unmap RX/TX for VM ID %#x, not found.\n",
			   owner_vm_id);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Get send and receive buffers. */
	if (vm->mailbox.send == NULL || vm->mailbox.recv == NULL) {
		dlog_verbose(
			"No buffer pair registered on behalf of the caller.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Currently a mailbox size of 1 page is assumed. */
	send_pa_begin = pa_from_va(va_from_ptr(vm->mailbox.send));
	send_pa_end = pa_add(send_pa_begin, HF_MAILBOX_SIZE);
	recv_pa_begin = pa_from_va(va_from_ptr(vm->mailbox.recv));
	recv_pa_end = pa_add(recv_pa_begin, HF_MAILBOX_SIZE);

	mm_stage1_locked = mm_lock_stage1();

	/* Reset stage 2 mapping only for virtual FF-A instances. */
	if (vm_id_is_current_world(owner_vm_id)) {
		/*
		 * Set the memory region of the buffers back to the default mode
		 * for the VM. Since this memory region was already mapped for
		 * the RXTX buffers we can safely remap them.
		 */
		CHECK(vm_identity_map(vm_locked, send_pa_begin, send_pa_end,
				      MM_MODE_R | MM_MODE_W | MM_MODE_X,
				      &api_page_pool, NULL));

		CHECK(vm_identity_map(vm_locked, recv_pa_begin, recv_pa_end,
				      MM_MODE_R | MM_MODE_W | MM_MODE_X,
				      &api_page_pool, NULL));
	}

	/* Unmap the buffers in the partition manager. */
	CHECK(mm_unmap(mm_stage1_locked, send_pa_begin, send_pa_end,
		       &api_page_pool));
	CHECK(mm_unmap(mm_stage1_locked, recv_pa_begin, recv_pa_end,
		       &api_page_pool));

	vm->mailbox.send = NULL;
	vm->mailbox.recv = NULL;
	plat_ffa_vm_destroy(vm_locked);

	/* Forward buffer unmapping to SPMC if coming from a VM. */
	plat_ffa_rxtx_unmap_forward(vm_locked);

	mm_unlock_stage1(&mm_stage1_locked);

out:
	vm_unlock(&vm_locked);

	return ret;
}

/**
 * Copies data from the sender's send buffer to the recipient's receive buffer
 * and notifies the receiver.
 */
struct ffa_value api_ffa_msg_send2(ffa_id_t sender_vm_id, uint32_t flags,
				   struct vcpu *current)
{
	struct vm *from = current->vm;
	struct vm *to;
	struct vm_locked to_locked;
	ffa_id_t msg_sender_id;
	struct vm_locked sender_locked;
	const void *from_msg;
	struct ffa_value ret;
	struct ffa_partition_rxtx_header header;
	ffa_id_t sender_id;
	ffa_id_t receiver_id;
	uint32_t msg_size;
	ffa_notifications_bitmap_t rx_buffer_full;

	/* Only Hypervisor can set `sender_vm_id` when forwarding messages. */
	if (from->id != HF_HYPERVISOR_VM_ID && sender_vm_id != 0) {
		dlog_error("Sender VM ID must be zero.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Get message sender's mailbox, which can be different to the `from` vm
	 * when the message is forwarded.
	 */
	msg_sender_id = (sender_vm_id != 0) ? sender_vm_id : from->id;
	sender_locked = plat_ffa_vm_find_locked(msg_sender_id);
	if (sender_locked.vm == NULL) {
		dlog_error("Cannot send message from VM ID %#x, not found.\n",
			   msg_sender_id);
		return ffa_error(FFA_DENIED);
	}

	from_msg = sender_locked.vm->mailbox.send;
	if (from_msg == NULL) {
		dlog_error("Cannot retrieve TX buffer for VM ID %#x.\n",
			   msg_sender_id);
		ret = ffa_error(FFA_DENIED);
		goto out_unlock_sender;
	}

	/*
	 * Copy message header as safety measure to avoid multiple accesses to
	 * unsafe memory which could be 'corrupted' between safety checks and
	 * final buffer copy.
	 */
	memcpy_s(&header, FFA_RXTX_HEADER_SIZE, from_msg, FFA_RXTX_HEADER_SIZE);
	sender_id = ffa_rxtx_header_sender(&header);
	receiver_id = ffa_rxtx_header_receiver(&header);

	/* Ensure Sender IDs from API and from message header match. */
	if (msg_sender_id != sender_id) {
		dlog_error(
			"Message sender VM ID (%#x) doesn't match header's VM "
			"ID (%#x).\n",
			msg_sender_id, sender_id);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_unlock_sender;
	}

	/* Disallow reflexive requests as this suggests an error in the VM. */
	if (receiver_id == sender_id) {
		dlog_error("Sender and receive VM IDs must be different.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_unlock_sender;
	}

	/* `flags` can be set only at secure virtual FF-A instances. */
	if (ffa_is_vm_id(sender_id) && (flags != 0)) {
		dlog_error("flags must be zero.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if the message has to be forwarded to the SPMC, in
	 * this case return, the SPMC will handle the buffer copy.
	 */
	if (plat_ffa_msg_send2_forward(receiver_id, sender_id, &ret)) {
		goto out_unlock_sender;
	}

	/* Ensure the receiver VM exists. */
	to_locked = plat_ffa_vm_find_locked(receiver_id);
	to = to_locked.vm;

	if (to == NULL) {
		dlog_error("Cannot deliver message to VM %#x, not found.\n",
			   receiver_id);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_unlock_sender;
	}

	/*
	 * Check sender and receiver can use indirect messages.
	 * Sender is the VM/SP who originally sent the message, not the
	 * hypervisor possibly relaying it.
	 */
	if (!plat_ffa_is_indirect_msg_supported(sender_locked, to_locked)) {
		dlog_verbose("VM %#x doesn't support indirect message\n",
			     sender_id);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (vm_is_mailbox_busy(to_locked)) {
		dlog_error(
			"Cannot deliver message to VM %#x, RX buffer not "
			"ready.\n",
			receiver_id);
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	/* Acquire receiver's RX buffer. */
	if (!plat_ffa_acquire_receiver_rx(to_locked, &ret)) {
		dlog_error("Failed to acquire RX buffer for VM %#x\n", to->id);
		goto out;
	}

	/* Check the size of transfer. */
	msg_size = FFA_RXTX_HEADER_SIZE + header.size;
	if ((msg_size > FFA_PARTITION_MSG_PAYLOAD_MAX) ||
	    (header.size > FFA_PARTITION_MSG_PAYLOAD_MAX)) {
		dlog_error("Message is too big.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Copy data. */
	memcpy_s(to->mailbox.recv, FFA_MSG_PAYLOAD_MAX, from_msg, msg_size);
	to->mailbox.recv_size = msg_size;
	to->mailbox.recv_sender = sender_id;
	to->mailbox.recv_func = FFA_MSG_SEND2_32;
	to->mailbox.state = MAILBOX_STATE_FULL;

	rx_buffer_full = ffa_is_vm_id(sender_id)
				 ? FFA_NOTIFICATION_HYP_BUFFER_FULL_MASK
				 : FFA_NOTIFICATION_SPM_BUFFER_FULL_MASK;
	vm_notifications_framework_set_pending(to_locked, rx_buffer_full);

	if ((FFA_NOTIFICATIONS_FLAG_DELAY_SRI & flags) == 0) {
		dlog_verbose("SRI was NOT delayed. vcpu: %u!\n",
			     vcpu_index(current));
		plat_ffa_sri_trigger_not_delayed(current->cpu);
	} else {
		plat_ffa_sri_state_set(DELAYED);
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	vm_unlock(&to_locked);

out_unlock_sender:
	vm_unlock(&sender_locked);

	return ret;
}

/**
 * Releases the caller's mailbox so that a new message can be received. The
 * caller must have copied out all data they wish to preserve as new messages
 * will overwrite the old and will arrive asynchronously.
 *
 * Returns:
 *  - FFA_ERROR FFA_INVALID_PARAMETERS if message is forwarded to SPMC but
 *    there's no buffer pair mapped.
 *  - FFA_ERROR FFA_DENIED on failure, if the mailbox hasn't been read.
 *  - FFA_SUCCESS on success if no further action is needed.
 *  - FFA_RX_RELEASE if it was called by the primary VM and the primary VM now
 *    needs to wake up or kick waiters. Waiters should be retrieved by calling
 *    hf_mailbox_waiter_get.
 */
struct ffa_value api_ffa_rx_release(ffa_id_t receiver_id, struct vcpu *current)
{
	struct vm *current_vm = current->vm;
	struct vm *vm;
	struct vm_locked vm_locked;
	ffa_id_t current_vm_id = current_vm->id;
	ffa_id_t release_vm_id;
	struct ffa_value ret;
	int32_t error_code;

	/* `receiver_id` can be set only at Non-Secure Physical interface. */
	if (vm_id_is_current_world(current_vm_id) && (receiver_id != 0)) {
		dlog_error("Invalid `receiver_id`, must be zero.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * VM ID to be released: `receiver_id` if message has been forwarded by
	 * Hypervisor to release a VM's buffer, current VM ID otherwise.
	 */
	if (vm_id_is_current_world(current_vm_id) || (receiver_id == 0)) {
		release_vm_id = current_vm_id;
	} else {
		release_vm_id = receiver_id;
	}

	vm_locked = plat_ffa_vm_find_locked(release_vm_id);
	vm = vm_locked.vm;
	if (vm == NULL) {
		dlog_error("No buffer registered for VM ID %#x.\n",
			   release_vm_id);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (plat_ffa_rx_release_forward(vm_locked, &ret)) {
		goto out;
	}

	if (!api_release_mailbox(vm_locked, &error_code)) {
		ret = ffa_error(error_code);
		goto out;
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	vm_unlock(&vm_locked);

	return ret;
}

/**
 * Acquire ownership of an RX buffer before writing to it. Both
 * Hypervisor and SPMC are producers of VM's RX buffer, and they
 * could contend for the same buffer. SPMC owns VM's RX buffer after
 * it's mapped in its translation regime. This ABI should be
 * used by the Hypervisor to get the ownership of a VM's RX buffer
 * from the SPMC solving the aforementioned possible contention.
 *
 * Returns:
 * - FFA_DENIED: callee cannot relinquish ownership of RX buffer.
 * - FFA_INVALID_PARAMETERS: there is no buffer pair registered for the VM.
 * - FFA_NOT_SUPPORTED: function not implemented at the FF-A instance.
 */
struct ffa_value api_ffa_rx_acquire(ffa_id_t receiver_id, struct vcpu *current)
{
	struct vm_locked receiver_locked;
	struct vm *receiver;
	struct ffa_value ret;

	if ((current->vm->id != HF_HYPERVISOR_VM_ID) ||
	    !ffa_is_vm_id(receiver_id)) {
		dlog_error(
			"FFA_RX_ACQUIRE not supported at this FF-A "
			"instance.\n");
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	receiver_locked = plat_ffa_vm_find_locked(receiver_id);
	receiver = receiver_locked.vm;

	if (receiver == NULL || receiver->mailbox.recv == NULL) {
		dlog_error("Cannot retrieve RX buffer for VM ID %#x.\n",
			   receiver_id);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (receiver->mailbox.state != MAILBOX_STATE_EMPTY) {
		dlog_error("Mailbox busy for VM ID %#x.\n", receiver_id);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	receiver->mailbox.state = MAILBOX_STATE_OTHER_WORLD_OWNED;

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	vm_unlock(&receiver_locked);

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
	struct interrupts *interrupts = &current->interrupts;

	if (intid >= HF_NUM_INTIDS) {
		return -1;
	}

	current_locked = vcpu_lock(current);
	if (enable) {
		/*
		 * If it is pending and was not enabled before, increment the
		 * count.
		 */
		if (vcpu_is_virt_interrupt_pending(interrupts, intid) &&
		    !vcpu_is_virt_interrupt_enabled(interrupts, intid)) {
			vcpu_interrupt_count_increment(current_locked,
						       interrupts, intid);
		}
		vcpu_virt_interrupt_set_enabled(interrupts, intid);
		vcpu_virt_interrupt_set_type(interrupts, intid, type);
	} else {
		/*
		 * If it is pending and was enabled before, decrement the count.
		 */
		if (vcpu_is_virt_interrupt_pending(interrupts, intid) &&
		    vcpu_is_virt_interrupt_enabled(interrupts, intid)) {
			vcpu_interrupt_count_decrement(current_locked,
						       interrupts, intid);
		}
		vcpu_virt_interrupt_clear_enabled(interrupts, intid);
		vcpu_virt_interrupt_set_type(interrupts, intid,
					     INTERRUPT_TYPE_IRQ);
	}

	vcpu_unlock(&current_locked);
	return 0;
}

static void api_interrupt_clear_decrement(struct vcpu_locked locked_vcpu,
					  struct interrupts *interrupts,
					  uint32_t intid)
{
	vcpu_virt_interrupt_clear_pending(interrupts, intid);
	vcpu_interrupt_count_decrement(locked_vcpu, interrupts, intid);
}

/**
 * Returns the ID of the next pending interrupt for the calling vCPU, and
 * acknowledges it (i.e. marks it as no longer pending). Returns
 * HF_INVALID_INTID if there are no pending interrupts.
 */
uint32_t api_interrupt_get(struct vcpu *current)
{
	uint32_t i;
	uint32_t first_interrupt = HF_INVALID_INTID;
	struct vcpu_locked current_locked;
	struct interrupts *interrupts = &current->interrupts;

	/*
	 * Find the first enabled and pending interrupt ID, return it, and
	 * deactivate it.
	 */
	current_locked = vcpu_lock(current);
	for (i = 0; i < HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS; ++i) {
		uint32_t enabled_and_pending =
			interrupts->interrupt_enabled.bitmap[i] &
			interrupts->interrupt_pending.bitmap[i];

		if (enabled_and_pending != 0) {
			uint8_t bit_index = ctz(enabled_and_pending);

			first_interrupt =
				i * INTERRUPT_REGISTER_BITS + bit_index;

			/*
			 * Mark it as no longer pending and decrement the count.
			 */
			api_interrupt_clear_decrement(
				current_locked, interrupts, first_interrupt);
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
int64_t api_interrupt_inject(ffa_id_t target_vm_id,
			     ffa_vcpu_index_t target_vcpu_idx, uint32_t intid,
			     struct vcpu *current, struct vcpu **next)
{
	struct vcpu *target_vcpu;
	struct vm *target_vm = vm_find(target_vm_id);
	struct vcpu_locked current_locked;
	struct vcpu_locked target_locked;
	struct two_vcpu_locked vcpus_locked;
	int64_t ret;

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

	/* A VM could inject an interrupt for itself. */
	if (target_vcpu != current) {
		/* Lock both vCPUs at once to avoid deadlock. */
		vcpus_locked = vcpu_lock_both(current, target_vcpu);
		current_locked = vcpus_locked.vcpu1;
		target_locked = vcpus_locked.vcpu2;
	} else {
		current_locked = vcpu_lock(current);
		target_locked = current_locked;
	}

	dlog_verbose(
		"Injecting interrupt %u for VM %#x vCPU %u from VM %#x vCPU "
		"%u\n",
		intid, target_vm_id, target_vcpu_idx, current->vm->id,
		vcpu_index(current));
	ret = api_interrupt_inject_locked(target_locked, intid, current_locked,
					  next);
	if (target_vcpu != current) {
		vcpu_unlock(&target_locked);
	}

	vcpu_unlock(&current_locked);
	return ret;
}

/** Returns the version of the implemented FF-A specification. */
struct ffa_value api_ffa_version(struct vcpu *current,
				 uint32_t requested_version)
{
	struct vm_locked current_vm_locked;

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

	if ((requested_version >> FFA_VERSION_MAJOR_OFFSET) !=
		    FFA_VERSION_MAJOR ||
	    requested_version > FFA_VERSION_COMPILED) {
		dlog_error("Version %x incompatible with %x\n",
			   requested_version, FFA_VERSION_COMPILED);
		return (struct ffa_value){.func = (uint32_t)FFA_NOT_SUPPORTED};
	}

	current_vm_locked = vm_lock(current->vm);
	current_vm_locked.vm->ffa_version = requested_version;
	vm_unlock(&current_vm_locked);

	return ((struct ffa_value){.func = FFA_VERSION_COMPILED});
}

/**
 * Helper for success return of FFA_FEATURES, for when it is used to query
 * an interrupt ID.
 */
struct ffa_value api_ffa_feature_success(uint32_t arg2)
{
	return (struct ffa_value){
		.func = FFA_SUCCESS_32, .arg1 = 0U, .arg2 = arg2};
}

/**
 * Discovery function returning information about the implementation of optional
 * FF-A interfaces.
 */
struct ffa_value api_ffa_features(uint32_t feature_function_id,
				  uint32_t input_property, uint32_t ffa_version)
{
	/*
	 * According to table 13.8 of FF-A v1.1 Beta 0 spec, bits [30:8] MBZ
	 * if using a feature ID.
	 */
	if ((feature_function_id & FFA_FEATURES_FUNC_ID_MASK) == 0U &&
	    (feature_function_id & ~FFA_FEATURES_FEATURE_ID_MASK) != 0U) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	if (feature_function_id != FFA_MEM_RETRIEVE_REQ_32 &&
	    input_property != 0U) {
		dlog_verbose(
			"input_property must be zero.\ninput_property = %u.\n",
			input_property);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	switch (feature_function_id) {
	/* Check support of the given Function ID. */
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
	case FFA_MSG_WAIT_32:
	case FFA_RUN_32:
	case FFA_MEM_DONATE_32:
	case FFA_MEM_LEND_32:
	case FFA_MEM_SHARE_32:
	case FFA_MEM_RETRIEVE_RESP_32:
	case FFA_MEM_RELINQUISH_32:
	case FFA_MEM_RECLAIM_32:
	case FFA_MEM_FRAG_RX_32:
	case FFA_MEM_FRAG_TX_32:
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
	/* FF-A v1.1 features. */
	case FFA_SPM_ID_GET_32:
	case FFA_NOTIFICATION_BITMAP_CREATE_32:
	case FFA_NOTIFICATION_BITMAP_DESTROY_32:
	case FFA_NOTIFICATION_BIND_32:
	case FFA_NOTIFICATION_UNBIND_32:
	case FFA_NOTIFICATION_SET_32:
	case FFA_NOTIFICATION_GET_32:
	case FFA_NOTIFICATION_INFO_GET_64:
	case FFA_MEM_PERM_GET_32:
	case FFA_MEM_PERM_SET_32:
	case FFA_MEM_PERM_GET_64:
	case FFA_MEM_PERM_SET_64:
	case FFA_MSG_SEND2_32:
	case FFA_PARTITION_INFO_GET_REGS_64:
#endif
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	case FFA_MEM_RETRIEVE_REQ_32:
		if ((input_property & FFA_FEATURES_MEM_RETRIEVE_REQ_MBZ_MASK) !=
		    0U) {
			dlog_verbose(
				"Bits[31:2] and Bit[0] of input_property must "
				"be zero.\ninput_property = %u.\n",
				input_property);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}

		if (ffa_version >= MAKE_FFA_VERSION(1, 1)) {
			if ((input_property &
			     FFA_FEATURES_MEM_RETRIEVE_REQ_NS_SUPPORT) == 0U) {
				dlog_verbose("NS bit support must be 1.\n");
				return ffa_error(FFA_INVALID_PARAMETERS);
			}
		}

		return api_ffa_feature_success(
			FFA_FEATURES_MEM_RETRIEVE_REQ_BUFFER_SUPPORT |
			(input_property &
			 FFA_FEATURES_MEM_RETRIEVE_REQ_NS_SUPPORT) |
			FFA_FEATURES_MEM_RETRIEVE_REQ_HYPERVISOR_SUPPORT);

#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
	/* Check support of a feature provided respective feature ID. */
	case FFA_FEATURE_NPI:
		return api_ffa_feature_success(HF_NOTIFICATION_PENDING_INTID);
	case FFA_FEATURE_SRI:
		return api_ffa_feature_success(HF_SCHEDULE_RECEIVER_INTID);
#endif
	/* Platform specific feature support. */
	default:
		return arch_ffa_features(feature_function_id);
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
struct ffa_value api_ffa_msg_send_direct_req(ffa_id_t sender_vm_id,
					     ffa_id_t receiver_vm_id,
					     struct ffa_value args,
					     struct vcpu *current,
					     struct vcpu **next)
{
	struct ffa_value ret;
	struct vm *receiver_vm;
	struct vm_locked receiver_locked;
	struct vcpu *receiver_vcpu;
	struct vcpu_locked current_locked;
	struct vcpu_locked receiver_vcpu_locked;
	struct two_vcpu_locked vcpus_locked;
	enum vcpu_state next_state = VCPU_STATE_RUNNING;

	if (!api_ffa_dir_msg_is_arg2_zero(args)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (!plat_ffa_is_direct_request_valid(current, sender_vm_id,
					      receiver_vm_id)) {
		dlog_verbose("Invalid direct message request.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (plat_ffa_direct_request_forward(receiver_vm_id, args, &ret)) {
		return ret;
	}

	ret = (struct ffa_value){.func = FFA_INTERRUPT_32};

	receiver_vm = vm_find(receiver_vm_id);
	if (receiver_vm == NULL) {
		dlog_verbose("Invalid Receiver!\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Check if sender supports sending direct message req, and if
	 * receiver supports receipt of direct message requests.
	 */
	if (!plat_ffa_is_direct_request_supported(current->vm, receiver_vm)) {
		return ffa_error(FFA_DENIED);
	}

	/*
	 * Per FF-A EAC spec section 4.4.1 the firmware framework supports
	 * UP (migratable) or MP partitions with a number of vCPUs matching the
	 * number of PEs in the system. It further states that MP partitions
	 * accepting direct request messages cannot migrate.
	 */
	receiver_vcpu = api_ffa_get_vm_vcpu(receiver_vm, current);
	if (receiver_vcpu == NULL) {
		dlog_verbose("Invalid vCPU!\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * If VM must be locked, it must be done before any of its vCPUs are
	 * locked.
	 */
	receiver_locked = vm_lock(receiver_vm);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, receiver_vcpu);
	current_locked = vcpus_locked.vcpu1;
	receiver_vcpu_locked = vcpus_locked.vcpu2;

	if (!plat_ffa_check_runtime_state_transition(
		    current_locked, sender_vm_id, HF_INVALID_VM_ID,
		    receiver_vcpu_locked, args.func, &next_state)) {
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/*
	 * If destination vCPU is executing or already received an
	 * FFA_MSG_SEND_DIRECT_REQ then return to caller hinting recipient is
	 * busy. There is a brief period of time where the vCPU state has
	 * changed but regs_available is still false thus consider this case as
	 * the vCPU not yet ready to receive a direct message request.
	 */
	if (is_ffa_direct_msg_request_ongoing(receiver_vcpu_locked) ||
	    receiver_vcpu->state == VCPU_STATE_RUNNING ||
	    !receiver_vcpu->regs_available) {
		dlog_verbose("Receiver is busy with another request.\n");
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	if (atomic_load_explicit(&receiver_vcpu->vm->aborting,
				 memory_order_relaxed)) {
		if (receiver_vcpu->state != VCPU_STATE_ABORTED) {
			dlog_verbose(
				"Receiver VM %#x aborted, cannot run vCPU %u\n",
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
	case VCPU_STATE_BLOCKED_INTERRUPT:
	case VCPU_STATE_BLOCKED:
	case VCPU_STATE_PREEMPTED:
		dlog_verbose("Receiver's vCPU can't receive request (%u)!\n",
			     vcpu_index(receiver_vcpu));
		ret = ffa_error(FFA_BUSY);
		goto out;
	case VCPU_STATE_WAITING:
		/*
		 * We expect target vCPU to be in WAITING state after either
		 * having called ffa_msg_wait or sent a direct message response.
		 */
		break;
	}

	/* Inject timer interrupt if any pending */
	if (arch_timer_pending(&receiver_vcpu->regs)) {
		api_interrupt_inject_locked(receiver_vcpu_locked,
					    HF_VIRTUAL_TIMER_INTID,
					    current_locked, NULL);

		arch_timer_mask(&receiver_vcpu->regs);
	}

	/* The receiver vCPU runs upon direct message invocation */
	receiver_vcpu->cpu = current->cpu;
	receiver_vcpu->state = VCPU_STATE_RUNNING;
	receiver_vcpu->regs_available = false;
	receiver_vcpu->direct_request_origin_vm_id = sender_vm_id;

	arch_regs_set_retval(&receiver_vcpu->regs, api_ffa_dir_msg_value(args));

	assert(!vm_id_is_current_world(current->vm->id) ||
	       next_state == VCPU_STATE_BLOCKED);
	current->state = VCPU_STATE_BLOCKED;

	plat_ffa_wind_call_chain_ffa_direct_req(
		current_locked, receiver_vcpu_locked, sender_vm_id);

	/* Switch to receiver vCPU targeted to by direct msg request */
	*next = receiver_vcpu;

	if (!receiver_locked.vm->el0_partition) {
		/*
		 * If the scheduler in the system is giving CPU cycles to the
		 * receiver, due to pending notifications, inject the NPI
		 * interrupt. Following call assumes that '*next' has been set
		 * to receiver_vcpu.
		 */
		plat_ffa_inject_notification_pending_interrupt(
			receiver_vcpu_locked, current_locked, receiver_locked);
	}

	/*
	 * Since this flow will lead to a VM switch, the return value will not
	 * be applied to current vCPU.
	 */

out:
	vcpu_unlock(&receiver_vcpu_locked);
	vm_unlock(&receiver_locked);
	vcpu_unlock(&current_locked);

	return ret;
}

/**
 * Resume the target vCPU after the current vCPU sent a direct response.
 * Current vCPU moves to waiting state.
 */
void api_ffa_resume_direct_resp_target(struct vcpu_locked current_locked,
				       struct vcpu **next,
				       ffa_id_t receiver_vm_id,
				       struct ffa_value to_ret,
				       bool is_nwd_call_chain)
{
	if (plat_ffa_is_spmd_lp_id(receiver_vm_id) ||
	    !vm_id_is_current_world(receiver_vm_id)) {
		*next = api_switch_to_other_world(current_locked, to_ret,
						  VCPU_STATE_WAITING);

		/* End of NWd scheduled call chain. */
		assert(!is_nwd_call_chain ||
		       (current_locked.vcpu->call_chain.prev_node == NULL));
	} else if (receiver_vm_id == HF_PRIMARY_VM_ID) {
		*next = api_switch_to_primary(current_locked, to_ret,
					      VCPU_STATE_WAITING);
	} else if (vm_id_is_current_world(receiver_vm_id)) {
		/*
		 * It is expected the receiver_vm_id to be from an SP, otherwise
		 * 'plat_ffa_is_direct_response_valid' should have
		 * made function return error before getting to this point.
		 */
		*next = api_switch_to_vm(current_locked, to_ret,
					 VCPU_STATE_WAITING, receiver_vm_id);
	} else {
		panic("Invalid direct message response invocation");
	}
}

/**
 * Send an FF-A direct message response.
 */
struct ffa_value api_ffa_msg_send_direct_resp(ffa_id_t sender_vm_id,
					      ffa_id_t receiver_vm_id,
					      struct ffa_value args,
					      struct vcpu *current,
					      struct vcpu **next)
{
	struct vcpu_locked current_locked;
	struct vcpu_locked next_locked = (struct vcpu_locked){
		.vcpu = NULL,
	};
	enum vcpu_state next_state = VCPU_STATE_RUNNING;
	struct ffa_value ret = (struct ffa_value){.func = FFA_INTERRUPT_32};
	struct ffa_value signal_interrupt =
		(struct ffa_value){.func = FFA_INTERRUPT_32};
	struct ffa_value to_ret = api_ffa_dir_msg_value(args);
	struct two_vcpu_locked vcpus_locked;

	if (!api_ffa_dir_msg_is_arg2_zero(args)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (!plat_ffa_is_direct_response_valid(current, sender_vm_id,
					       receiver_vm_id)) {
		dlog_verbose("Invalid direct response call.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	current_locked = vcpu_lock(current);

	if (!plat_ffa_check_runtime_state_transition(
		    current_locked, sender_vm_id, receiver_vm_id, next_locked,
		    args.func, &next_state)) {
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (plat_ffa_is_direct_response_interrupted(current_locked)) {
		ret = ffa_error(FFA_INTERRUPTED);
		goto out;
	}

	assert(!vm_id_is_current_world(current->vm->id) ||
	       next_state == VCPU_STATE_WAITING);

	/*
	 * Ensure the terminating FFA_MSG_SEND_DIRECT_REQ had a
	 * defined originator.
	 */
	if (!is_ffa_direct_msg_request_ongoing(current_locked)) {
		/*
		 * Sending direct response but direct request origin
		 * vCPU is not set.
		 */
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (api_ffa_is_managed_exit_ongoing(current_locked)) {
		/*
		 * Per FF-A v1.1 EAC0 section 8.3.1.2.1 rule 6, SPMC can signal
		 * a secure interrupt to a SP that is performing managed exit.
		 * We have taken a implementation defined choice to not allow
		 * Managed exit while a SP is processing a secure interrupt.
		 */
		CHECK(!current->processing_secure_interrupt);

		plat_interrupts_set_priority_mask(current->priority_mask);
		/*
		 * A SP may be signaled a managed exit but actually not trap
		 * the virtual interrupt, probably because it has virtual
		 * interrupts masked, and emit direct resp. In this case the
		 * managed exit operation is considered completed and it would
		 * also need to clear the pending managed exit flag for the SP
		 * vCPU.
		 */
		current->processing_managed_exit = false;
		struct interrupts *interrupts = &current->interrupts;

		if (vcpu_is_virt_interrupt_pending(interrupts,
						   HF_MANAGED_EXIT_INTID)) {
			api_interrupt_clear_decrement(current_locked,
						      interrupts,
						      HF_MANAGED_EXIT_INTID);
		}
	}

	if (plat_ffa_intercept_direct_response(current_locked, next, to_ret,
					       &signal_interrupt)) {
		ret = signal_interrupt;
		goto out;
	}

	/* Clear direct request origin for the caller. */
	current->direct_request_origin_vm_id = HF_INVALID_VM_ID;

	api_ffa_resume_direct_resp_target(current_locked, next, receiver_vm_id,
					  to_ret, false);

	/*
	 * Unlock current vCPU to allow it to be locked together with next
	 * vcpu.
	 */
	vcpu_unlock(&current_locked);

	/* Lock both vCPUs at once to avoid deadlock. */
	vcpus_locked = vcpu_lock_both(current, *next);
	current_locked = vcpus_locked.vcpu1;
	next_locked = vcpus_locked.vcpu2;

	plat_ffa_unwind_call_chain_ffa_direct_resp(current_locked, next_locked);
	vcpu_unlock(&next_locked);

out:
	vcpu_unlock(&current_locked);
	return ret;
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

/*
 * Convert memory transaction descriptor from FF-A v1.0 to FF-A v1.1 EAC0.
 */
static void api_ffa_memory_region_v1_1_from_v1_0(
	struct ffa_memory_region_v1_0 *memory_region_v1_0,
	struct ffa_memory_region *memory_region_v1_1)
{
	memory_region_v1_1->sender = memory_region_v1_0->sender;
	memory_region_v1_1->handle = memory_region_v1_0->handle;
	memory_region_v1_1->attributes = memory_region_v1_0->attributes;
	memory_region_v1_1->flags = memory_region_v1_0->flags;
	memory_region_v1_1->tag = memory_region_v1_0->tag;
	memory_region_v1_1->memory_access_desc_size =
		sizeof(struct ffa_memory_access);
	memory_region_v1_1->receiver_count = memory_region_v1_0->receiver_count;
	memory_region_v1_1->receivers_offset =
		offsetof(struct ffa_memory_region, receivers);

	/* Zero reserved fields. */
	for (uint32_t i = 0; i < 3U; i++) {
		memory_region_v1_1->reserved[i] = 0U;
	}
}

/*
 * Checks the FF-A version of the lender and makes necessary updates.
 */
static struct ffa_value api_ffa_memory_send_per_ffa_version(
	void *allocated, struct ffa_memory_region **out_v1_1,
	uint32_t *fragment_length, uint32_t *total_length, uint32_t ffa_version)
{
	struct ffa_memory_region_v1_0 *memory_region_v1_0;
	struct ffa_memory_region *memory_region_v1_1 = NULL;
	struct ffa_composite_memory_region *composite_v1_0;
	struct ffa_composite_memory_region *composite_v1_1;
	size_t receivers_length;
	size_t space_left;
	size_t composite_offset_v1_1;
	size_t composite_offset_v1_0;
	size_t fragment_constituents_size;
	size_t fragment_length_v1_1;

	assert(out_v1_1 != NULL);
	assert(fragment_length != NULL);
	assert(total_length != NULL);

	*out_v1_1 = (struct ffa_memory_region *)allocated;

	if (ffa_version == MAKE_FFA_VERSION(1, 1)) {
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	}

	if (ffa_version != MAKE_FFA_VERSION(1, 0)) {
		dlog_verbose("%s: Unsupported FF-A version %x\n", __func__,
			     ffa_version);
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	dlog_verbose("FF-A v1.0 memory transaction descriptor.\n");

	memory_region_v1_0 = (struct ffa_memory_region_v1_0 *)allocated;

	if (memory_region_v1_0->reserved_0 != 0U ||
	    memory_region_v1_0->reserved_1 != 0U) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* This should also prevent over flows. */
	if (memory_region_v1_0->receiver_count > MAX_MEM_SHARE_RECIPIENTS) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	receivers_length = sizeof(struct ffa_memory_access) *
			   memory_region_v1_0->receiver_count;

	/*
	 * Check the specified composite offset of v1.0 descriptor, and that all
	 * receivers were configured with the same offset.
	 */
	composite_offset_v1_0 =
		memory_region_v1_0->receivers[0].composite_memory_region_offset;

	if (composite_offset_v1_0 == 0U ||
	    composite_offset_v1_0 <
		    sizeof(struct ffa_memory_region_v1_0) + receivers_length ||
	    composite_offset_v1_0 + sizeof(struct ffa_composite_memory_region) >
		    *fragment_length ||
	    composite_offset_v1_0 > *fragment_length) {
		dlog_verbose(
			"Invalid composite memory region descriptor offset "
			"%d.\n",
			composite_offset_v1_0);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	for (uint32_t i = 1; i < memory_region_v1_0->receiver_count; i++) {
		const uint32_t current_offset =
			memory_region_v1_0->receivers[i]
				.composite_memory_region_offset;

		if (current_offset != composite_offset_v1_0) {
			dlog_verbose(
				"Composite offset %x differs from %x in index "
				"%u\n",
				composite_offset_v1_0, current_offset, i);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	}

	fragment_constituents_size = *fragment_length - composite_offset_v1_0 -
				     sizeof(struct ffa_composite_memory_region);

	/* Determine the composite offset for v1.1 descriptor. */
	composite_offset_v1_1 =
		sizeof(struct ffa_memory_region) + receivers_length;

	/* Determine final size of the v1.1 descriptor. */
	fragment_length_v1_1 = composite_offset_v1_1 +
			       sizeof(struct ffa_composite_memory_region) +
			       fragment_constituents_size;

	/*
	 * Currently only support the simpler cases: memory transaction
	 * in a single fragment that fits in a MM_PPOOL_ENTRY_SIZE.
	 * TODO: allocate the entries needed for this fragment_length_v1_1.
	 *      - Check corner when v1.1 descriptor converted size surpasses
	 *        the size of the entry.
	 */
	if (fragment_length_v1_1 > MM_PPOOL_ENTRY_SIZE) {
		dlog_verbose(
			"Translation of FF-A v1.0 descriptors for over %u is "
			"unsupported.",
			MM_PPOOL_ENTRY_SIZE);
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	space_left = fragment_length_v1_1;

	memory_region_v1_1 =
		(struct ffa_memory_region *)mpool_alloc(&api_page_pool);
	if (memory_region_v1_1 == NULL) {
		return ffa_error(FFA_NO_MEMORY);
	}

	/* Translate header from v1.0 to v1.1. */
	api_ffa_memory_region_v1_1_from_v1_0(memory_region_v1_0,
					     memory_region_v1_1);

	space_left -= sizeof(struct ffa_memory_region);

	/* Copy memory access information. */
	memcpy_s(memory_region_v1_1->receivers, space_left,
		 memory_region_v1_0->receivers, receivers_length);

	/* Initialize the memory access descriptors with composite offset. */
	for (uint32_t i = 0; i < memory_region_v1_1->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			&memory_region_v1_1->receivers[i];

		receiver->composite_memory_region_offset =
			composite_offset_v1_1;
	}

	space_left -= receivers_length;

	/* Init v1.1 composite. */
	composite_v1_1 = (struct ffa_composite_memory_region
				  *)((uint8_t *)memory_region_v1_1 +
				     composite_offset_v1_1);

	composite_v1_0 =
		ffa_memory_region_get_composite_v1_0(memory_region_v1_0, 0);
	composite_v1_1->constituent_count = composite_v1_0->constituent_count;
	composite_v1_1->page_count = composite_v1_0->page_count;

	space_left -= sizeof(struct ffa_composite_memory_region);

	/* Initialize v1.1 constituents. */
	memcpy_s(composite_v1_1->constituents, space_left,
		 composite_v1_0->constituents, fragment_constituents_size);

	space_left -= fragment_constituents_size;
	assert(space_left == 0U);

	*out_v1_1 = memory_region_v1_1;

	/*
	 * Remove the v1.0 fragment size, and resultant size of v1.1 fragment.
	 */
	*total_length = *total_length - *fragment_length + fragment_length_v1_1;
	*fragment_length = fragment_length_v1_1;

	/*
	 * After successfully convert to v1.1 free memory containing v1.0
	 * descriptor.
	 */
	mpool_free(&api_page_pool, allocated);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value api_ffa_mem_send(uint32_t share_func, uint32_t length,
				  uint32_t fragment_length, ipaddr_t address,
				  uint32_t page_count, struct vcpu *current)
{
	struct vm *from = current->vm;
	struct vm *to;
	const void *from_msg;
	void *allocated_entry;
	struct ffa_memory_region *memory_region;
	struct ffa_value ret;
	bool targets_other_world = false;
	uint32_t ffa_version;

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

	if (fragment_length > HF_MAILBOX_SIZE ||
	    fragment_length > MM_PPOOL_ENTRY_SIZE) {
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
	ffa_version = from->ffa_version;
	sl_unlock(&from->lock);

	if (from_msg == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Copy the memory region descriptor to a fresh page from the memory
	 * pool. This prevents the sender from changing it underneath us, and
	 * also lets us keep it around in the share state table if needed.
	 */
	allocated_entry = mpool_alloc(&api_page_pool);
	if (allocated_entry == NULL) {
		dlog_verbose("Failed to allocate memory region copy.\n");
		return ffa_error(FFA_NO_MEMORY);
	}

	memcpy_s(allocated_entry, MM_PPOOL_ENTRY_SIZE, from_msg,
		 fragment_length);

	ret = api_ffa_memory_send_per_ffa_version(
		allocated_entry, &memory_region, &fragment_length, &length,
		ffa_version);
	if (ret.func != FFA_SUCCESS_32) {
		goto out;
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

	if (!api_memory_region_check_flags(memory_region, share_func)) {
		dlog_verbose(
			"Memory region reserved arguments must be zero.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->receiver_count == 0U) {
		dlog_verbose("Receiver count can't be 0.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (share_func == FFA_MEM_DONATE_32 &&
	    memory_region->receiver_count != 1U) {
		dlog_verbose(
			"FFA_MEM_DONATE only supports one recipient. "
			"Specified %u\n",
			memory_region->receiver_count);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->receiver_count > MAX_MEM_SHARE_RECIPIENTS) {
		dlog_verbose(
			"Max number of recipients supported is %u "
			"specified %u\n",
			MAX_MEM_SHARE_RECIPIENTS,
			memory_region->receiver_count);
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Ensure that the receiver VM exists and isn't the same as the sender.
	 * If there is a receiver from the other world, track it for later
	 * forwarding if needed.
	 */
	for (uint32_t i = 0U; i < memory_region->receiver_count; i++) {
		ffa_id_t receiver_id = memory_region->receivers[i]
					       .receiver_permissions.receiver;
		to = vm_find(receiver_id);

		if (vm_id_is_current_world(receiver_id) &&
		    (to == NULL || to == from)) {
			dlog_verbose("%s: invalid receiver.\n", __func__);
			ret = ffa_error(FFA_INVALID_PARAMETERS);
			goto out;
		}

		if (!plat_ffa_is_memory_send_valid(receiver_id, share_func)) {
			ret = ffa_error(FFA_DENIED);
			goto out;
		}

		/* Capture if any of the receivers is from the other world. */
		if (!targets_other_world) {
			targets_other_world =
				!vm_id_is_current_world(receiver_id);
		}
	}

	if (targets_other_world) {
		ret = plat_ffa_other_world_mem_send(
			from, share_func, &memory_region, length,
			fragment_length, &api_page_pool);
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

static struct ffa_value api_ffa_mem_retrieve_req_version_update(
	void *retrieve_msg, uint32_t retrieve_msg_buffer_size,
	struct ffa_memory_region **out_v1_1, uint32_t *fragment_length,
	uint32_t ffa_version)
{
	struct ffa_memory_region_v1_0 *retrieve_request_v1_0;
	struct ffa_memory_region *retrieve_request_v1_1;
	size_t fragment_length_v1_1;
	uint32_t expected_retrieve_request_length_v1_0;
	size_t space_left = retrieve_msg_buffer_size;
	size_t receivers_length;

	assert(out_v1_1 != NULL);
	assert(fragment_length != NULL);
	assert(retrieve_msg != NULL);

	if (ffa_version == MAKE_FFA_VERSION(1, 1)) {
		*out_v1_1 = (struct ffa_memory_region *)retrieve_msg;
		return (struct ffa_value){.func = FFA_SUCCESS_32};
	}
	if (ffa_version != MAKE_FFA_VERSION(1, 0)) {
		dlog_verbose("%s: Unsupported FF-A version %x\n", __func__,
			     ffa_version);
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	retrieve_request_v1_0 = (struct ffa_memory_region_v1_0 *)retrieve_msg;

	if (retrieve_request_v1_0->receiver_count > MAX_MEM_SHARE_RECIPIENTS) {
		dlog_verbose(
			"Specified more than expected maximum receivers.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	receivers_length = retrieve_request_v1_0->receiver_count *
			   sizeof(struct ffa_memory_access);

	expected_retrieve_request_length_v1_0 =
		sizeof(struct ffa_memory_region_v1_0) + receivers_length;

	if (*fragment_length != expected_retrieve_request_length_v1_0) {
		dlog_verbose("Retrieve request size is not as expected.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Determine expected v1.1 retrieve request size. */
	fragment_length_v1_1 = sizeof(struct ffa_memory_region) +
			       retrieve_request_v1_0->receiver_count *
				       sizeof(struct ffa_memory_access);

	/*
	 * At this point there is the assumption that the retrieve request has
	 * been copied to an internal buffer to prevent TOCTOU attacks.
	 * The translation of the resultant v1.1 transaction descriptor will be
	 * written to that same buffer. That said, the referred buffer needs
	 * space to accommodate both v1.0 and v1.1 descriptors simultaneously.
	 */
	assert(fragment_length_v1_1 + expected_retrieve_request_length_v1_0 <=
	       retrieve_msg_buffer_size);

	space_left -= expected_retrieve_request_length_v1_0;

	/*
	 * Prepare to write the resultant FF-A v1.1 retrieve request in an
	 * offset following the FF-A v1.0 within the same buffer.
	 */
	retrieve_request_v1_1 =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct ffa_memory_region *)((uintptr_t)retrieve_msg +
					     *fragment_length);

	api_ffa_memory_region_v1_1_from_v1_0(retrieve_request_v1_0,
					     retrieve_request_v1_1);

	space_left -= sizeof(struct ffa_memory_region);

	/* Copy memory access information. */
	memcpy_s(retrieve_request_v1_1->receivers, space_left,
		 retrieve_request_v1_0->receivers, receivers_length);

	/* Initialize the memory access descriptors with composite offset. */
	for (uint32_t i = 0; i < retrieve_request_v1_1->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			&retrieve_request_v1_1->receivers[i];

		receiver->composite_memory_region_offset = 0U;
	}

	*fragment_length = fragment_length_v1_1;
	*out_v1_1 = retrieve_request_v1_1;

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value api_ffa_mem_retrieve_req(uint32_t length,
					  uint32_t fragment_length,
					  ipaddr_t address, uint32_t page_count,
					  struct vcpu *current)
{
	struct vm *to = current->vm;
	struct vm_locked to_locked;
	const void *to_msg;
	void *retrieve_msg;
	struct ffa_memory_region *retrieve_request = NULL;
	uint32_t message_buffer_size;
	struct ffa_value ret;
	uint32_t ffa_version;

	if (ipa_addr(address) != 0 || page_count != 0) {
		/*
		 * Hafnium only supports passing the descriptor in the TX
		 * mailbox.
		 */
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (fragment_length != length) {
		dlog_verbose("Fragmentation not supported.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	retrieve_msg = cpu_get_buffer(current->cpu);
	message_buffer_size = cpu_get_buffer_size(current->cpu);
	if (length > HF_MAILBOX_SIZE || length > message_buffer_size) {
		dlog_verbose("Retrieve request too long.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	to_locked = vm_lock(to);
	to_msg = to->mailbox.send;
	ffa_version = to->ffa_version;

	if (to_msg == NULL) {
		dlog_verbose("TX buffer not setup.\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/*
	 * Copy the retrieve request descriptor to an internal buffer, so that
	 * the caller can't change it underneath us.
	 */
	memcpy_s(retrieve_msg, message_buffer_size, to_msg, length);

	if ((vm_is_mailbox_other_world_owned(to_locked) &&
	     !plat_ffa_acquire_receiver_rx(to_locked, &ret)) ||
	    vm_is_mailbox_busy(to_locked)) {
		/*
		 * Can't retrieve memory information if the mailbox is
		 * not available.
		 */
		dlog_verbose("%s: RX buffer not ready.\n", __func__);
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	/*
	 * If required, transform the retrieve request to FF-A v1.1.
	 */
	ret = api_ffa_mem_retrieve_req_version_update(
		retrieve_msg, message_buffer_size, &retrieve_request, &length,
		ffa_version);

	if (ret.func != FFA_SUCCESS_32) {
		goto out;
	}

	assert(retrieve_request != NULL);

	if (plat_ffa_memory_handle_allocated_by_current_world(
		    retrieve_request->handle)) {
		ret = ffa_memory_retrieve(to_locked, retrieve_request, length,
					  &api_page_pool);
	} else {
		ret = plat_ffa_other_world_mem_retrieve(
			to_locked, retrieve_request, length, &api_page_pool);
	}
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
			 sizeof(ffa_id_t);
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
		    relinquish_request->endpoint_count * sizeof(ffa_id_t) !=
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
		ret = plat_ffa_other_world_mem_reclaim(to, handle, flags,
						       &api_page_pool);
	}

	return ret;
}

struct ffa_value api_ffa_mem_frag_rx(ffa_memory_handle_t handle,
				     uint32_t fragment_offset,
				     ffa_id_t sender_vm_id,
				     struct vcpu *current)
{
	struct vm *to = current->vm;
	struct vm_locked to_locked;
	struct ffa_value ret;

	/* Sender ID MBZ at virtual instance. */
	if (vm_id_is_current_world(to->id)) {
		if (sender_vm_id != 0) {
			dlog_verbose("%s: Invalid sender.\n", __func__);
			return ffa_error(FFA_INVALID_PARAMETERS);
		}
	}

	to_locked = vm_lock(to);

	if (vm_is_mailbox_busy(to_locked)) {
		/*
		 * Can't retrieve memory information if the mailbox is not
		 * available.
		 */
		dlog_verbose("%s: RX buffer not ready partition %x.\n",
			     __func__, to_locked.vm->id);
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	ret = ffa_memory_retrieve_continue(to_locked, handle, fragment_offset,
					   sender_vm_id, &api_page_pool);
out:
	vm_unlock(&to_locked);
	return ret;
}

struct ffa_value api_ffa_mem_frag_tx(ffa_memory_handle_t handle,
				     uint32_t fragment_length,
				     ffa_id_t sender_vm_id,
				     struct vcpu *current)
{
	struct vm *from = current->vm;
	const void *from_msg;
	void *fragment_copy;
	struct ffa_value ret;

	/* Sender ID MBZ at virtual instance. */
	if (vm_id_is_current_world(from->id) && sender_vm_id != 0) {
		dlog_verbose("Invalid sender.");
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
		dlog_verbose("Mailbox from %x is not set.\n", from->id);
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
	 * other world or not.
	 */
	if (plat_ffa_memory_handle_allocated_by_current_world(handle)) {
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
		ret = plat_ffa_other_world_mem_send_continue(
			from, fragment_copy, fragment_length, handle,
			&api_page_pool);
	}

	return ret;
}

/**
 * Register an entry point for a vCPU in warm boot cases.
 * DEN0077A FF-A v1.1 Beta0 section 18.3.2.1 FFA_SECONDARY_EP_REGISTER.
 */
struct ffa_value api_ffa_secondary_ep_register(ipaddr_t entry_point,
					       struct vcpu *current)
{
	struct vm_locked vm_locked;
	struct vcpu_locked current_locked;

	/*
	 * Reject if interface is not supported at this FF-A instance
	 * (DEN0077A FF-A v1.1 Beta0 Table 18.29) or the VM is UP.
	 */
	if (!plat_ffa_is_secondary_ep_register_supported() ||
	    current->vm->vcpu_count == 1) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	/*
	 * No further check is made on the address validity
	 * (FF-A v1.1 Beta0 Table 18.29) as the VM boundaries are not known
	 * from the VM or vCPU structure.
	 * DEN0077A FF-A v1.1 Beta0 section 18.3.2.1.1:
	 * For each SP [...] the Framework assumes that the same entry point
	 * address is used for initializing any execution context during a
	 * secondary cold boot.
	 * If this function is invoked multiple times, then the entry point
	 * address specified in the last valid invocation must be used by the
	 * callee.
	 */
	current_locked = vcpu_lock(current);
	if (current->rt_model != RTM_SP_INIT) {
		dlog_error(
			"FFA_SECONDARY_EP_REGISTER can only be called while "
			"vCPU in run-time state for initialization.\n");
		vcpu_unlock(&current_locked);
		return ffa_error(FFA_DENIED);
	}
	vcpu_unlock(&current_locked);

	vm_locked = vm_lock(current->vm);
	vm_locked.vm->secondary_ep = entry_point;
	vm_unlock(&vm_locked);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value api_ffa_notification_bitmap_create(ffa_id_t vm_id,
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

struct ffa_value api_ffa_notification_bitmap_destroy(ffa_id_t vm_id,
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
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, bool is_bind,
	struct vcpu *current)
{
	struct ffa_value ret = {.func = FFA_SUCCESS_32};
	struct vm_locked receiver_locked;
	const bool is_per_vcpu = (flags & FFA_NOTIFICATION_FLAG_PER_VCPU) != 0U;
	const ffa_id_t id_to_update = is_bind ? sender_vm_id : HF_INVALID_VM_ID;
	const ffa_id_t id_to_validate =
		is_bind ? HF_INVALID_VM_ID : sender_vm_id;
	const uint32_t flags_mbz =
		is_bind ? ~FFA_NOTIFICATIONS_FLAG_PER_VCPU : ~0U;

	if ((flags_mbz & flags) != 0U) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (!plat_ffa_is_notifications_bind_valid(current, sender_vm_id,
						  receiver_vm_id)) {
		dlog_verbose("Invalid use of notifications bind interface.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (plat_ffa_notifications_update_bindings_forward(
		    receiver_vm_id, sender_vm_id, flags, notifications, is_bind,
		    &ret)) {
		return ret;
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

	if (!vm_locked_are_notifications_enabled(receiver_locked)) {
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
		    receiver_locked, ffa_is_vm_id(sender_vm_id), id_to_validate,
		    notifications)) {
		dlog_verbose("Notifications are bound to other sender.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/**
	 * Check if there is a pending notification within those specified in
	 * the bitmap.
	 */
	if (vm_are_notifications_pending(receiver_locked,
					 ffa_is_vm_id(sender_vm_id),
					 notifications)) {
		dlog_verbose("Notifications within '%x' pending.\n",
			     notifications);
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	vm_notifications_update_bindings(
		receiver_locked, ffa_is_vm_id(sender_vm_id), id_to_update,
		notifications, is_per_vcpu && is_bind);

out:
	vm_unlock(&receiver_locked);
	return ret;
}

struct ffa_value api_ffa_notification_set(
	ffa_id_t sender_vm_id, ffa_id_t receiver_vm_id, uint32_t flags,
	ffa_notifications_bitmap_t notifications, struct vcpu *current)
{
	struct ffa_value ret;
	struct vm_locked receiver_locked;

	/*
	 * Check if is per-vCPU or global, and extracting vCPU ID according
	 * to table 17.19 of the FF-A v1.1 Beta 0 spec.
	 */
	bool is_per_vcpu = (flags & FFA_NOTIFICATION_FLAG_PER_VCPU) != 0U;
	ffa_vcpu_index_t vcpu_id = (uint16_t)(flags >> 16);

	if (!plat_ffa_is_notification_set_valid(current, sender_vm_id,
						receiver_vm_id)) {
		dlog_verbose("Invalid use of notifications set interface.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (notifications == 0U) {
		dlog_verbose("No notifications have been specified.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (plat_ffa_notification_set_forward(sender_vm_id, receiver_vm_id,
					      flags, notifications, &ret)) {
		return ret;
	}

	/*
	 * This check assumes receiver is the current VM, and has been enforced
	 * by 'plat_ffa_is_notification_set_valid'.
	 */
	receiver_locked = plat_ffa_vm_find_locked(receiver_vm_id);

	if (receiver_locked.vm == NULL) {
		dlog_verbose("Receiver ID is not valid.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if (!vm_locked_are_notifications_enabled(receiver_locked)) {
		dlog_verbose("Receiver's notifications not enabled.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	/*
	 * If notifications are not bound to the sender, they wouldn't be
	 * enabled either for the receiver.
	 */
	if (!vm_notifications_validate_binding(
		    receiver_locked, ffa_is_vm_id(sender_vm_id), sender_vm_id,
		    notifications, is_per_vcpu)) {
		dlog_verbose("Notifications bindings not valid.\n");
		ret = ffa_error(FFA_DENIED);
		goto out;
	}

	if (is_per_vcpu && vcpu_id >= receiver_locked.vm->vcpu_count) {
		dlog_verbose("Invalid VCPU ID!\n");
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Set notifications pending. */
	vm_notifications_partition_set_pending(
		receiver_locked, ffa_is_vm_id(sender_vm_id), notifications,
		vcpu_id, is_per_vcpu);

	dlog_verbose("Set the notifications: %x.\n", notifications);

	if ((FFA_NOTIFICATIONS_FLAG_DELAY_SRI & flags) == 0) {
		dlog_verbose("SRI was NOT delayed. vcpu: %u!\n",
			     vcpu_index(current));
		plat_ffa_sri_trigger_not_delayed(current->cpu);
	} else {
		plat_ffa_sri_state_set(DELAYED);
	}

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};
out:
	vm_unlock(&receiver_locked);

	return ret;
}

static struct ffa_value api_ffa_notification_get_success_return(
	ffa_notifications_bitmap_t from_sp, ffa_notifications_bitmap_t from_vm,
	ffa_notifications_bitmap_t from_framework)
{
	return (struct ffa_value){
		.func = FFA_SUCCESS_32,
		.arg1 = 0U,
		.arg2 = (uint32_t)from_sp,
		.arg3 = (uint32_t)(from_sp >> 32),
		.arg4 = (uint32_t)from_vm,
		.arg5 = (uint32_t)(from_vm >> 32),
		.arg6 = (uint32_t)from_framework,
		.arg7 = (uint32_t)(from_framework >> 32),
	};
}

struct ffa_value api_ffa_notification_get(ffa_id_t receiver_vm_id,
					  ffa_vcpu_index_t vcpu_id,
					  uint32_t flags, struct vcpu *current)
{
	ffa_notifications_bitmap_t framework_notifications = 0;
	ffa_notifications_bitmap_t sp_notifications = 0;
	ffa_notifications_bitmap_t vm_notifications = 0;
	struct vm_locked receiver_locked;
	struct ffa_value ret;
	const uint32_t flags_mbz = ~(FFA_NOTIFICATION_FLAG_BITMAP_HYP |
				     FFA_NOTIFICATION_FLAG_BITMAP_SPM |
				     FFA_NOTIFICATION_FLAG_BITMAP_SP |
				     FFA_NOTIFICATION_FLAG_BITMAP_VM);

	/* The FF-A v1.1 EAC0 specification states bits [31:4] Must Be Zero. */
	if ((flags & flags_mbz) != 0U) {
		dlog_verbose(
			"Invalid flags bit(s) set in notifications get. [31:4] "
			"MBZ(%x)\n",
			flags);
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Following check should capture wrong uses of the interface,
	 * depending on whether Hafnium is SPMC or hypervisor. On the
	 * rest of the function it is assumed this condition is met.
	 */
	if (!plat_ffa_is_notification_get_valid(current, receiver_vm_id,
						flags)) {
		dlog_verbose("Invalid use of notifications get interface.\n");
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * This check assumes receiver is the current VM, and has been enforced
	 * by `plat_ffa_is_notifications_get_valid`.
	 */
	receiver_locked = plat_ffa_vm_find_locked(receiver_vm_id);

	/*
	 * `plat_ffa_is_notifications_get_valid` ensures following is never
	 * true.
	 */
	CHECK(receiver_locked.vm != NULL);

	if (receiver_locked.vm->vcpu_count <= vcpu_id ||
	    (receiver_locked.vm->vcpu_count != 1 &&
	     cpu_index(current->cpu) != vcpu_id)) {
		dlog_verbose(
			"Invalid VCPU ID %u. vcpu count %u current core: %u!\n",
			vcpu_id, receiver_locked.vm->vcpu_count,
			cpu_index(current->cpu));
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	if ((flags & FFA_NOTIFICATION_FLAG_BITMAP_SP) != 0U) {
		if (!plat_ffa_notifications_get_from_sp(
			    receiver_locked, vcpu_id, &sp_notifications,
			    &ret)) {
			dlog_verbose("Failed to get notifications from sps.");
			goto out;
		}
	}

	if ((flags & FFA_NOTIFICATION_FLAG_BITMAP_VM) != 0U) {
		vm_notifications = vm_notifications_partition_get_pending(
			receiver_locked, true, vcpu_id);
	}

	if ((flags & FFA_NOTIFICATION_FLAG_BITMAP_HYP) != 0U ||
	    (flags & FFA_NOTIFICATION_FLAG_BITMAP_SPM) != 0U) {
		if (!plat_ffa_notifications_get_framework_notifications(
			    receiver_locked, &framework_notifications, flags,
			    vcpu_id, &ret)) {
			dlog_verbose(
				"Failed to get notifications from "
				"framework.\n");
			goto out;
		}
	}

	ret = api_ffa_notification_get_success_return(
		sp_notifications, vm_notifications, framework_notifications);

	/*
	 * If there are no more pending notifications, change `sri_state` to
	 * handled.
	 */
	if (vm_is_notifications_pending_count_zero()) {
		plat_ffa_sri_state_set(HANDLED);
	}

	if (!receiver_locked.vm->el0_partition &&
	    !vm_are_global_notifications_pending(receiver_locked)) {
		vm_notifications_set_npi_injected(receiver_locked, false);
	}

out:
	vm_unlock(&receiver_locked);

	return ret;
}

/**
 * Prepares successful return for FFA_NOTIFICATION_INFO_GET, as described by
 * the section 17.7.1 of the FF-A v1.1 Beta0 specification.
 */
static struct ffa_value api_ffa_notification_info_get_success_return(
	const uint16_t *ids, uint32_t ids_count, const uint32_t *lists_sizes,
	uint32_t lists_count)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_64};

	/*
	 * Copying content of ids into ret structure. Use 5 registers (x3-x7) to
	 * hold the list of ids.
	 */
	memcpy_s(&ret.arg3,
		 sizeof(ret.arg3) * FFA_NOTIFICATIONS_INFO_GET_REGS_RET, ids,
		 sizeof(ids[0]) * ids_count);

	/*
	 * According to the spec x2 should have:
	 * - Bit flagging if there are more notifications pending;
	 * - The total number of elements (i.e. total list size);
	 * - The number of VCPU IDs within each VM specific list.
	 */
	ret.arg2 = vm_notifications_pending_not_retrieved_by_scheduler()
			   ? FFA_NOTIFICATIONS_INFO_GET_FLAG_MORE_PENDING
			   : 0;

	ret.arg2 |= (lists_count & FFA_NOTIFICATIONS_LISTS_COUNT_MASK)
		    << FFA_NOTIFICATIONS_LISTS_COUNT_SHIFT;

	for (unsigned int i = 0; i < lists_count; i++) {
		ret.arg2 |= (lists_sizes[i] & FFA_NOTIFICATIONS_LIST_SIZE_MASK)
			    << FFA_NOTIFICATIONS_LIST_SHIFT(i + 1);
	}

	return ret;
}

struct ffa_value api_ffa_notification_info_get(struct vcpu *current)
{
	/*
	 * Following set of variables should be populated with the return info.
	 * At a successfull handling of this interface, they should be used
	 * to populate the 'ret' structure in accordance to the table 17.29
	 * of the FF-A v1.1 Beta0 specification.
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS];
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	uint32_t ids_count = 0;
	bool list_is_full = false;
	struct ffa_value result;

	/*
	 * This interface can only be called at NS virtual/physical FF-A
	 * instance by the endpoint implementing the primary scheduler and the
	 * Hypervisor/OS kernel.
	 * In the SPM, following check passes if call has been forwarded from
	 * the hypervisor.
	 */
	if (current->vm->id != HF_PRIMARY_VM_ID) {
		dlog_verbose(
			"Only the receiver's scheduler can use this "
			"interface\n");
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	/*
	 * Forward call to the other world, and fill the arrays used to assemble
	 * return.
	 */
	plat_ffa_notification_info_get_forward(
		ids, &ids_count, lists_sizes, &lists_count,
		FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

	list_is_full = ids_count == FFA_NOTIFICATIONS_INFO_GET_MAX_IDS;

	/* Get notifications' info from this world */
	for (ffa_vm_count_t index = 0; index < vm_get_count() && !list_is_full;
	     ++index) {
		struct vm_locked vm_locked = vm_lock(vm_find_index(index));

		list_is_full = vm_notifications_info_get(
			vm_locked, ids, &ids_count, lists_sizes, &lists_count,
			FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

		vm_unlock(&vm_locked);
	}

	if (!list_is_full) {
		/* Grab notifications info from other world */
		plat_ffa_vm_notifications_info_get(
			ids, &ids_count, lists_sizes, &lists_count,
			FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);
	}

	if (ids_count == 0) {
		dlog_verbose(
			"Notification info get has no data to retrieve.\n");
		result = ffa_error(FFA_NO_DATA);
	} else {
		result = api_ffa_notification_info_get_success_return(
			ids, ids_count, lists_sizes, lists_count);
	}

	plat_ffa_sri_state_set(HANDLED);

	return result;
}

struct ffa_value api_ffa_mem_perm_get(vaddr_t base_addr, struct vcpu *current)
{
	struct vm_locked vm_locked;
	struct ffa_value ret = ffa_error(FFA_INVALID_PARAMETERS);
	bool mode_ret = false;
	uint32_t mode = 0;

	if (!plat_ffa_is_mem_perm_get_valid(current)) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	if (!(current->vm->el0_partition)) {
		return ffa_error(FFA_DENIED);
	}

	vm_locked = vm_lock(current->vm);

	/*
	 * mm_get_mode is used to check if the given base_addr page is already
	 * mapped. If the page is unmapped, return error. If the page is mapped
	 * appropriate attributes are returned to the caller. Note that
	 * mm_get_mode returns true if the address is in the valid VA range as
	 * supported by the architecture and MMU configurations, as opposed to
	 * whether a page is mapped or not. For a page to be known as mapped,
	 * the API must return true AND the returned mode must not have
	 * MM_MODE_INVALID set.
	 */
	mode_ret = mm_get_mode(&vm_locked.vm->ptable, base_addr,
			       va_add(base_addr, PAGE_SIZE), &mode);
	if (!mode_ret || (mode & MM_MODE_INVALID)) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* No memory should be marked RWX */
	CHECK((mode & (MM_MODE_R | MM_MODE_W | MM_MODE_X)) !=
	      (MM_MODE_R | MM_MODE_W | MM_MODE_X));

	/*
	 * S-EL0 partitions are expected to have all their pages marked as
	 * non-global.
	 */
	CHECK((mode & (MM_MODE_NG | MM_MODE_USER)) ==
	      (MM_MODE_NG | MM_MODE_USER));

	if (mode & MM_MODE_W) {
		/* No memory should be writeable but not readable. */
		CHECK(mode & MM_MODE_R);
		ret = (struct ffa_value){.func = FFA_SUCCESS_32,
					 .arg2 = (uint32_t)(FFA_MEM_PERM_RW)};
	} else if (mode & MM_MODE_R) {
		ret = (struct ffa_value){.func = FFA_SUCCESS_32,
					 .arg2 = (uint32_t)(FFA_MEM_PERM_RX)};
		if (!(mode & MM_MODE_X)) {
			ret.arg2 = (uint32_t)(FFA_MEM_PERM_RO);
		}
	}
out:
	vm_unlock(&vm_locked);
	return ret;
}

struct ffa_value api_ffa_mem_perm_set(vaddr_t base_addr, uint32_t page_count,
				      uint32_t mem_perm, struct vcpu *current)
{
	struct vm_locked vm_locked;
	struct ffa_value ret;
	bool mode_ret = false;
	uint32_t original_mode;
	uint32_t new_mode;
	struct mpool local_page_pool;

	if (!plat_ffa_is_mem_perm_set_valid(current)) {
		return ffa_error(FFA_NOT_SUPPORTED);
	}

	if (!(current->vm->el0_partition)) {
		return ffa_error(FFA_DENIED);
	}

	if (!is_aligned(va_addr(base_addr), PAGE_SIZE)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	if ((mem_perm != FFA_MEM_PERM_RW) && (mem_perm != FFA_MEM_PERM_RO) &&
	    (mem_perm != FFA_MEM_PERM_RX)) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Create a local pool so any freed memory can't be used by another
	 * thread. This is to ensure the original mapping can be restored if any
	 * stage of the process fails.
	 */
	mpool_init_with_fallback(&local_page_pool, &api_page_pool);

	vm_locked = vm_lock(current->vm);

	/*
	 * All regions accessible by the partition are mapped during boot. If we
	 * cannot get a successful translation for the page range, the request
	 * to change permissions is rejected.
	 * mm_get_mode is used to check if the given address range is already
	 * mapped. If the range is unmapped, return error. If the range is
	 * mapped appropriate attributes are returned to the caller. Note that
	 * mm_get_mode returns true if the address is in the valid VA range as
	 * supported by the architecture and MMU configurations, as opposed to
	 * whether a page is mapped or not. For a page to be known as mapped,
	 * the API must return true AND the returned mode must not have
	 * MM_MODE_INVALID set.
	 */

	mode_ret = mm_get_mode(&vm_locked.vm->ptable, base_addr,
			       va_add(base_addr, page_count * PAGE_SIZE),
			       &original_mode);
	if (!mode_ret || (original_mode & MM_MODE_INVALID)) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	/* Device memory cannot be marked as executable */
	if ((original_mode & MM_MODE_D) && (mem_perm == FFA_MEM_PERM_RX)) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out;
	}

	new_mode = MM_MODE_USER | MM_MODE_NG;

	if (mem_perm == FFA_MEM_PERM_RW) {
		new_mode |= MM_MODE_R | MM_MODE_W;
	} else if (mem_perm == FFA_MEM_PERM_RX) {
		new_mode |= MM_MODE_R | MM_MODE_X;
	} else if (mem_perm == FFA_MEM_PERM_RO) {
		new_mode |= MM_MODE_R;
	}

	/*
	 * Safe to re-map memory, since we know the requested permissions are
	 * valid, and the memory requested to be re-mapped is also valid.
	 */
	if (!mm_identity_prepare(
		    &vm_locked.vm->ptable, pa_from_va(base_addr),
		    pa_from_va(va_add(base_addr, page_count * PAGE_SIZE)),
		    new_mode, &local_page_pool)) {
		/*
		 * Defrag the table into the local page pool.
		 * mm_identity_prepare could have allocated or freed pages to
		 * split blocks or tables etc.
		 */
		mm_stage1_defrag(&vm_locked.vm->ptable, &local_page_pool);

		/*
		 * Guaranteed to succeed mapping with old mode since the mapping
		 * with old mode already existed and we have a local page pool
		 * that should have sufficient memory to go back to the original
		 * state.
		 */
		CHECK(mm_identity_prepare(
			&vm_locked.vm->ptable, pa_from_va(base_addr),
			pa_from_va(va_add(base_addr, page_count * PAGE_SIZE)),
			original_mode, &local_page_pool));
		mm_identity_commit(
			&vm_locked.vm->ptable, pa_from_va(base_addr),
			pa_from_va(va_add(base_addr, page_count * PAGE_SIZE)),
			original_mode, &local_page_pool);

		mm_stage1_defrag(&vm_locked.vm->ptable, &api_page_pool);
		ret = ffa_error(FFA_NO_MEMORY);
		goto out;
	}

	mm_identity_commit(
		&vm_locked.vm->ptable, pa_from_va(base_addr),
		pa_from_va(va_add(base_addr, page_count * PAGE_SIZE)), new_mode,
		&local_page_pool);

	ret = (struct ffa_value){.func = FFA_SUCCESS_32};

out:
	mpool_fini(&local_page_pool);
	vm_unlock(&vm_locked);

	return ret;
}

/**
 * Helper function for FFA_CONSOLE_LOG ABI.
 * Writes number of characters to a given VM buffer.
 */
static rsize_t arg_to_char_helper(struct vm_locked from_locked,
				  const uint64_t src, rsize_t src_size,
				  rsize_t to_write)
{
	bool flush = false;
	char c;
	rsize_t size = src_size < to_write ? src_size : to_write;
	rsize_t written = 0;

	if (size == 0) {
		return 0;
	}

	while (written < size) {
		c = ((char *)&src)[written++];
		if (c == '\n' || c == '\0') {
			flush = true;
		} else {
			from_locked.vm->log_buffer
				[from_locked.vm->log_buffer_length++] = c;
			flush = (from_locked.vm->log_buffer_length ==
				 LOG_BUFFER_SIZE);
		}

		if (flush) {
			dlog_flush_vm_buffer(from_locked.vm->id,
					     from_locked.vm->log_buffer,
					     from_locked.vm->log_buffer_length);
			from_locked.vm->log_buffer_length = 0;
		}
	}

	return written;
}

/**
 * Implements FFA_CONSOLE_LOG buffered logging.
 */
struct ffa_value api_ffa_console_log(const struct ffa_value args,
				     struct vcpu *current)
{
	struct vm *vm = current->vm;
	struct vm_locked vm_locked;
	size_t chars_in_param = args.func == FFA_CONSOLE_LOG_32
					? sizeof(uint32_t)
					: sizeof(uint64_t);
	size_t total_to_write = args.arg1;

	if (total_to_write == 0 || total_to_write > chars_in_param * 6) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	vm_locked = vm_lock(vm);

	total_to_write -= arg_to_char_helper(vm_locked, args.arg2,
					     chars_in_param, total_to_write);
	total_to_write -= arg_to_char_helper(vm_locked, args.arg3,
					     chars_in_param, total_to_write);
	total_to_write -= arg_to_char_helper(vm_locked, args.arg4,
					     chars_in_param, total_to_write);
	total_to_write -= arg_to_char_helper(vm_locked, args.arg5,
					     chars_in_param, total_to_write);
	total_to_write -= arg_to_char_helper(vm_locked, args.arg6,
					     chars_in_param, total_to_write);
	arg_to_char_helper(vm_locked, args.arg7, chars_in_param,
			   total_to_write);

	vm_unlock(&vm_locked);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}
