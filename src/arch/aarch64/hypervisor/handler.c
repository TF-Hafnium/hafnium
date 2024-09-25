/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdnoreturn.h>

#include "hf/arch/barriers.h"
#include "hf/arch/gicv3.h"
#include "hf/arch/host_timer.h"
#include "hf/arch/init.h"
#include "hf/arch/memcpy_trapped.h"
#include "hf/arch/mmu.h"
#include "hf/arch/plat/ffa.h"
#include "hf/arch/plat/smc.h"
#include "hf/arch/timer.h"
#include "hf/arch/vmid_base.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/hf_ipi.h"
#include "hf/panic.h"
#include "hf/plat/interrupts.h"
#include "hf/timer_mgmt.h"
#include "hf/vm.h"
#include "hf/vm_ids.h"

#include "vmapi/hf/call.h"

#include "debug_el1.h"
#include "el1_physical_timer.h"
#include "feature_id.h"
#include "perfmon.h"
#include "psci.h"
#include "psci_handler.h"
#include "smc.h"
#include "sysregs.h"
#include "sysregs_defs.h"

/**
 * Hypervisor Fault Address Register Non-Secure.
 */
#define HPFAR_EL2_NS (UINT64_C(0x1) << 63)

/**
 * Hypervisor Fault Address Register Faulting IPA.
 */
#define HPFAR_EL2_FIPA (UINT64_C(0xFFFFFFFFFF0))

/**
 * Gets the value to increment for the next PC.
 * The ESR encodes whether the instruction is 2 bytes or 4 bytes long.
 */
#define GET_NEXT_PC_INC(esr) (GET_ESR_IL(esr) ? 4 : 2)

/**
 * The Client ID field within X7 for an SMC64 call.
 */
#define CLIENT_ID_MASK UINT64_C(0xffff)

/**
 * Identifies SPMD specific framework messages. See section 18.2 of v1.2 FF-A
 * specification.
 */
enum ffa_spmd_framework_msg_func {
	SPMD_FRAMEWORK_MSG_PSCI_REQ = 0,
	SPMD_FRAMEWORK_MSG_PSCI_RESP = 2,

	SPMD_FRAMEWORK_MSG_FFA_VERSION_REQ = 8,
	SPMD_FRAMEWORK_MSG_FFA_VERSION_RESP = 9,
};

/**
 * Returns a reference to the currently executing vCPU.
 */
static struct vcpu *current(void)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	return (struct vcpu *)read_msr(tpidr_el2);
}

/**
 * Saves the state of per-vCPU peripherals, such as the arch timer, and
 * informs the arch-independent sections that registers have been saved.
 */
void complete_saving_state(struct vcpu *vcpu)
{
	host_timer_save_arch_timer(&vcpu->regs.arch_timer);

	timer_vcpu_manage(vcpu);
	api_regs_state_saved(vcpu);

	/*
	 * Since switching away from current vCPU, disable the host physical
	 * timer for now. If necessary, the host timer will be reconfigured
	 * at appropriate time to track timer deadline of the vCPU.
	 */
	host_timer_disable();
}

/**
 * Restores the state of per-vCPU peripherals, such as the arch timer.
 */
void begin_restoring_state(struct vcpu *vcpu)
{
	/*
	 * If a vCPU's timer has expired while it was de-scheduled, SPMC will
	 * inject the virtual timer interrupt before resuming the vCPU.
	 * If not, there is a live state and we need to configure the host timer
	 * to track it again.
	 */
	if (arch_timer_enabled(&vcpu->regs) &&
	    (arch_timer_remaining_ns(&vcpu->regs) != 0)) {
		host_timer_track_deadline(&vcpu->regs.arch_timer);
	}
}

/**
 * Invalidate all stage 1 TLB entries on the current (physical) CPU for the
 * current VMID.
 */
static void invalidate_vm_tlb(void)
{
	/*
	 * Ensure that the last VTTBR write has taken effect so we invalidate
	 * the right set of TLB entries.
	 */
	isb();

	tlbi(vmalle1);

	/*
	 * Ensure that no instructions are fetched for the VM until after the
	 * TLB invalidation has taken effect.
	 */
	isb();

	/*
	 * Ensure that no data reads or writes for the VM happen until after the
	 * TLB invalidation has taken effect. Non-shareable is enough because
	 * the TLB is local to the CPU.
	 */
	dsb(nsh);
}

/**
 * Invalidates the TLB if a different vCPU is being run than the last vCPU of
 * the same VM which was run on the current pCPU.
 *
 * This is necessary because VMs may (contrary to the architecture
 * specification) use inconsistent ASIDs across vCPUs. c.f. KVM's similar
 * workaround:
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=94d0e5980d6791b9
 */
void maybe_invalidate_tlb(struct vcpu *vcpu)
{
	size_t current_cpu_index = cpu_index(vcpu->cpu);
	ffa_vcpu_index_t new_vcpu_index = vcpu_index(vcpu);

	if (vcpu->vm->arch.last_vcpu_on_cpu[current_cpu_index] !=
	    new_vcpu_index) {
		/*
		 * The vCPU has changed since the last time this VM was run on
		 * this pCPU, so we need to invalidate the TLB.
		 */
		invalidate_vm_tlb();

		/* Record the fact that this vCPU is now running on this CPU. */
		vcpu->vm->arch.last_vcpu_on_cpu[current_cpu_index] =
			new_vcpu_index;
	}
}

noreturn void irq_current_exception_noreturn(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("IRQ from current exception level.");
}

noreturn void fiq_current_exception_noreturn(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("FIQ from current exception level.");
}

noreturn void serr_current_exception_noreturn(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("SError from current exception level.");
}

/**
 * Returns true if ELR_EL2 is not to be restored from stack.
 * Currently function doesn't return false, as for all other cases
 * panics.
 */
bool sync_current_exception(uintreg_t elr, uintreg_t spsr)
{
	uintreg_t esr = read_msr(esr_el2);
	uintreg_t ec = GET_ESR_EC(esr);
	(void)spsr;

	switch (ec) {
	case EC_DATA_ABORT_SAME_EL: {
		uint64_t iss = GET_ESR_ISS(esr);
		uint64_t dfsc = GET_ESR_ISS_DFSC(iss);
		uint64_t far = read_msr(far_el2);

		/* Handle Granule Protection Fault. */
		if (is_arch_feat_rme_supported() && dfsc == DFSC_GPF) {
			dlog_verbose(
				"Granule Protection Fault: esr=%#lx, ec=%#lx, "
				"far=%#lx, elr=%#lx\n",
				esr, ec, far, elr);

			/*
			 * Change ELR_EL2 only if failed whilst either
			 * reading or writing within 'memcpy_trapped'.
			 */
			if (elr == (uintptr_t)memcpy_trapped_read ||
			    elr == (uintptr_t)memcpy_trapped_write) {
				dlog_verbose(
					"GPF due to data abort on %s.\n",
					(elr == (uintptr_t)memcpy_trapped_read)
						? "read"
						: "write");

				/*
				 * Update the ELR_EL2 with the return
				 * address, to return error from the
				 * call to 'memcpy_trapped'.
				 */
				write_msr(ELR_EL2, memcpy_trapped_aborted);
				return true;
			}
		}

#if ENABLE_MTE
		if (dfsc == DFSC_SYNC_TAG_CHECK_FAULT) {
			dlog_error(
				"Data abort due to synchronous tag check "
				"fault: pc=%#lx, esr=%#lx, ec=%#lx, "
				"far=%#lx, dfsc = %#lx\n",
				elr, esr, ec, far, dfsc);
		}
		break;
#endif
		if (!GET_ESR_FNV(esr)) {
			dlog_error(
				"Data abort: pc=%#lx, esr=%#lx, ec=%#lx, "
				"far=%#lx\n",
				elr, esr, ec, far);

		} else {
			dlog_error(
				"Data abort: pc=%#lx, esr=%#lx, ec=%#lx, "
				"far=invalid\n",
				elr, esr, ec);
		}
	} break;
	default:
		dlog_error(
			"Unknown current sync exception pc=%#lx, esr=%#lx, "
			"ec=%#lx\n",
			elr, esr, ec);
		break;
	}

	panic("EL2 exception");
}

/**
 * Sets or clears the VF bit in the HCR_EL2 register saved in the given
 * arch_regs.
 */
static void set_virtual_fiq(struct arch_regs *r, bool enable)
{
	if (enable) {
		r->hyp_state.hcr_el2 |= HCR_EL2_VF;
	} else {
		r->hyp_state.hcr_el2 &= ~HCR_EL2_VF;
	}
}

/**
 * Sets or clears the VI bit in the HCR_EL2 register saved in the given
 * arch_regs.
 */
static void set_virtual_irq(struct arch_regs *r, bool enable)
{
	if (enable) {
		r->hyp_state.hcr_el2 |= HCR_EL2_VI;
	} else {
		r->hyp_state.hcr_el2 &= ~HCR_EL2_VI;
	}
}

#if SECURE_WORLD == 1
/**
 * Handle special direct messages from SPMD to SPMC.
 */
static bool spmd_handler(struct ffa_value *args, struct vcpu *current)
{
	ffa_id_t sender = ffa_sender(*args);
	ffa_id_t receiver = ffa_receiver(*args);
	ffa_id_t current_vm_id = current->vm->id;
	enum ffa_spmd_framework_msg_func func =
		(enum ffa_spmd_framework_msg_func)ffa_framework_msg_func(*args);

	/*
	 * Check if direct message request is originating from the SPMD,
	 * directed to the SPMC and the message is a framework message.
	 */
	if (!(sender == HF_SPMD_VM_ID && receiver == HF_SPMC_VM_ID &&
	      current_vm_id == HF_OTHER_WORLD_ID &&
	      ffa_is_framework_msg(*args))) {
		return false;
	}

	/*
	 * The framework message is conveyed by EL3/SPMD to SPMC so the
	 * current VM id must match to the other world VM id.
	 */
	CHECK(current->vm->id == HF_HYPERVISOR_VM_ID);

	switch (func) {
	case SPMD_FRAMEWORK_MSG_PSCI_REQ: {
		enum psci_return_code psci_msg_response =
			PSCI_ERROR_NOT_SUPPORTED;
		struct vcpu *boot_vcpu = vcpu_get_boot_vcpu();
		struct vm *vm = boot_vcpu->vm;
		struct vcpu_locked vcpu_locked;

		/*
		 * TODO: the power management event reached the SPMC.
		 * In a later iteration, the power management event can
		 * be passed to the SP by resuming it.
		 */
		switch (args->arg3) {
		case PSCI_CPU_OFF: {
			if (vm_power_management_cpu_off_requested(vm) == true) {
				struct vcpu *vcpu;

				/* Allow only S-EL1 MP SPs to reach here. */
				CHECK(vm->el0_partition == false);
				CHECK(vm->vcpu_count > 1);

				vcpu = vm_get_vcpu(vm, vcpu_index(current));
				vcpu_locked = vcpu_lock(vcpu);
				vcpu->state = VCPU_STATE_OFF;
				vcpu_unlock(&vcpu_locked);
				cpu_off(vcpu->cpu);
				dlog_verbose("cpu%u off notification!\n",
					     vcpu_index(vcpu));
			}

			psci_msg_response = PSCI_RETURN_SUCCESS;
			break;
		}
		default:
			dlog_error(
				"FF-A PSCI framework message not handled "
				"%#lx %#lx %#lx %#lx\n",
				args->func, args->arg1, args->arg2, args->arg3);
			psci_msg_response = PSCI_ERROR_NOT_SUPPORTED;
		}

		*args = ffa_framework_msg_resp(HF_SPMC_VM_ID, HF_SPMD_VM_ID,
					       SPMD_FRAMEWORK_MSG_PSCI_RESP,
					       psci_msg_response);
		return true;
	}
	case SPMD_FRAMEWORK_MSG_FFA_VERSION_REQ: {
		struct ffa_value ret = api_ffa_version(current, args->arg3);
		*args = ffa_framework_msg_resp(
			HF_SPMC_VM_ID, HF_SPMD_VM_ID,
			SPMD_FRAMEWORK_MSG_FFA_VERSION_RESP, ret.func);
		return true;
	}
	default:
		dlog_error("FF-A framework message not handled %#lx\n",
			   args->arg2);

		/*
		 * TODO: the framework message that was conveyed by a direct
		 * request is not handled although we still want to complete
		 * by a direct response. However, there is no defined error
		 * response to state that the message couldn't be handled.
		 * An alternative would be to return FFA_ERROR.
		 */
		*args = ffa_framework_msg_resp(HF_SPMC_VM_ID, HF_SPMD_VM_ID,
					       func, 0);
		return true;
	}
}

void spmc_exit_to_nwd(struct vcpu *owd_vcpu)
{
	struct vcpu *deadline_vcpu =
		timer_find_vcpu_nearest_deadline(owd_vcpu->cpu);

	/*
	 * SPMC tracks a vCPU's timer deadline through its host timer such that
	 * it can bring back execution from normal world to signal the timer
	 * virtual interrupt to the SP's vCPU.
	 */
	if (deadline_vcpu != NULL) {
		host_timer_track_deadline(&deadline_vcpu->regs.arch_timer);
	}
}
#endif

/**
 * Checks whether to block an SMC being forwarded from a VM.
 */
static bool smc_is_blocked(const struct vm *vm, uint32_t func)
{
	bool block_by_default = !vm->smc_whitelist.permissive;

	for (size_t i = 0; i < vm->smc_whitelist.smc_count; ++i) {
		if (func == vm->smc_whitelist.smcs[i]) {
			return false;
		}
	}

	dlog_notice("SMC %#010x attempted from VM %#x, blocked=%u\n", func,
		    vm->id, block_by_default);

	/* Access is still allowed in permissive mode. */
	return block_by_default;
}

/**
 * Applies SMC access control according to manifest and forwards the call if
 * access is granted.
 */
static void smc_forwarder(const struct vm *vm, struct ffa_value *args)
{
	struct ffa_value ret;
	uint32_t client_id = vm->id;
	uintreg_t arg7 = args->arg7;

	if (smc_is_blocked(vm, args->func)) {
		args->func = SMCCC_ERROR_UNKNOWN;
		return;
	}

	/*
	 * Set the Client ID but keep the existing Secure OS ID and anything
	 * else (currently unspecified) that the client may have passed in the
	 * upper bits.
	 */
	args->arg7 = client_id | (arg7 & ~CLIENT_ID_MASK);
	ret = smc_forward(args->func, args->arg1, args->arg2, args->arg3,
			  args->arg4, args->arg5, args->arg6, args->arg7);

	/*
	 * Preserve the value passed by the caller, rather than the generated
	 * client_id. Note that this would also overwrite any return value that
	 * may be in x7, but the SMCs that we are forwarding are legacy calls
	 * from before SMCCC 1.2 so won't have more than 4 return values anyway.
	 */
	ret.arg7 = arg7;

	plat_smc_post_forward(*args, &ret);

	*args = ret;
}

/**
 * In the normal world, ffa_handler is always called from the virtual FF-A
 * instance (from a VM in EL1). In the secure world, ffa_handler may be called
 * from the virtual (a secure partition in S-EL1) or physical FF-A instance
 * (from the normal world via EL3). The function returns true when the call is
 * handled. The *next pointer is updated to the next vCPU to run, which might be
 * the 'other world' vCPU if the call originated from the virtual FF-A instance
 * and has to be forwarded down to EL3, or left as is to resume the current
 * vCPU.
 */
static bool ffa_handler(struct ffa_value *args, struct vcpu *current,
			struct vcpu **next)
{
	uint32_t func = args->func;

	/*
	 * NOTE: When adding new methods to this handler update
	 * api_ffa_features accordingly.
	 */
	switch (func) {
	case FFA_VERSION_32:
		*args = api_ffa_version(current, args->arg1);
		return true;
	case FFA_PARTITION_INFO_GET_32: {
		struct ffa_uuid uuid;

		ffa_uuid_init(args->arg1, args->arg2, args->arg3, args->arg4,
			      &uuid);
		*args = api_ffa_partition_info_get(current, &uuid, args->arg5);
		return true;
	}
	case FFA_PARTITION_INFO_GET_REGS_64: {
		struct ffa_uuid uuid;
		uint16_t start_index;
		uint16_t tag;

		ffa_uuid_from_u64x2(args->arg1, args->arg2, &uuid);
		start_index = args->arg3 & 0xFFFF;
		tag = (args->arg3 >> 16) & 0xFFFF;
		*args = api_ffa_partition_info_get_regs(current, &uuid,
							start_index, tag);
		return true;
	}
	case FFA_ID_GET_32:
		*args = api_ffa_id_get(current);
		return true;
	case FFA_SPM_ID_GET_32:
		*args = api_ffa_spm_id_get();
		return true;
	case FFA_FEATURES_32:
		*args = api_ffa_features(args->arg1, args->arg2, current);
		return true;
	case FFA_RX_RELEASE_32:
		*args = api_ffa_rx_release(ffa_receiver(*args), current);
		return true;
	case FFA_RXTX_MAP_64:
		*args = api_ffa_rxtx_map(ipa_init(args->arg1),
					 ipa_init(args->arg2), args->arg3,
					 current);
		return true;
	case FFA_RXTX_UNMAP_32:
		*args = api_ffa_rxtx_unmap(ffa_vm_id(*args), current);
		return true;
	case FFA_RX_ACQUIRE_32:
		*args = api_ffa_rx_acquire(ffa_receiver(*args), current);
		return true;
	case FFA_YIELD_32:
		*args = api_yield(current, next, args);
		return true;
	case FFA_MSG_SEND_32:
		*args = plat_ffa_msg_send(
			ffa_sender(*args), ffa_receiver(*args),
			ffa_msg_send_size(*args), current, next);
		return true;
	case FFA_MSG_SEND2_32:
		*args = api_ffa_msg_send2(ffa_sender(*args),
					  ffa_msg_send2_flags(*args), current);
		return true;
	case FFA_MSG_WAIT_32:
		*args = api_ffa_msg_wait(current, next, args);
		return true;
#if SECURE_WORLD == 0
	case FFA_MSG_POLL_32: {
		struct vcpu_locked current_locked;

		current_locked = vcpu_lock(current);
		*args = plat_ffa_msg_recv(false, current_locked, next);
		vcpu_unlock(&current_locked);
		return true;
	}
#endif
	case FFA_RUN_32:
		/**
		 * Ensure that an FF-A v1.2 endpoint preserves the
		 * runtime state of the calling partition by setting
		 * the extended registers (x8-x17) to zero.
		 */
		if (current->vm->ffa_version >= FFA_VERSION_1_2 &&
		    !api_extended_args_are_zero(args)) {
			*args = ffa_error(FFA_INVALID_PARAMETERS);
			return false;
		}
		*args = api_ffa_run(ffa_vm_id(*args), ffa_vcpu_index(*args),
				    current, next);
		return true;
	case FFA_MEM_DONATE_32:
	case FFA_MEM_DONATE_64:
	case FFA_MEM_LEND_32:
	case FFA_MEM_LEND_64:
	case FFA_MEM_SHARE_32:
	case FFA_MEM_SHARE_64:
		*args = api_ffa_mem_send(func, args->arg1, args->arg2,
					 ipa_init(args->arg3), args->arg4,
					 current);
		return true;
	case FFA_MEM_RETRIEVE_REQ_64:
	case FFA_MEM_RETRIEVE_REQ_32:
		*args = api_ffa_mem_retrieve_req(args->arg1, args->arg2,
						 ipa_init(args->arg3),
						 args->arg4, current);
		return true;
	case FFA_MEM_RELINQUISH_32:
		*args = api_ffa_mem_relinquish(current);
		return true;
	case FFA_MEM_RECLAIM_32:
		*args = api_ffa_mem_reclaim(
			ffa_assemble_handle(args->arg1, args->arg2), args->arg3,
			current);
		return true;
	case FFA_MEM_FRAG_RX_32:
		*args = api_ffa_mem_frag_rx(ffa_frag_handle(*args), args->arg3,
					    (args->arg4 >> 16) & 0xffff,
					    current);
		return true;
	case FFA_MEM_FRAG_TX_32:
		*args = api_ffa_mem_frag_tx(ffa_frag_handle(*args), args->arg3,
					    (args->arg4 >> 16) & 0xffff,
					    current);
		return true;
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
#if SECURE_WORLD == 1
		if (spmd_handler(args, current)) {
			return true;
		}
#endif
	case FFA_MSG_SEND_DIRECT_REQ2_64:
		*args = api_ffa_msg_send_direct_req(*args, current, next);
		return true;
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		*args = api_ffa_msg_send_direct_resp(*args, current, next);
		return true;
	case FFA_SECONDARY_EP_REGISTER_64:
		/*
		 * DEN0077A FF-A v1.1 Beta0 section 18.3.2.1.1
		 * The callee must return NOT_SUPPORTED if this function is
		 * invoked by a caller that implements version v1.0 of
		 * the Framework.
		 */
		*args = api_ffa_secondary_ep_register(ipa_init(args->arg1),
						      current);
		return true;
	case FFA_NOTIFICATION_BITMAP_CREATE_32:
		*args = api_ffa_notification_bitmap_create(
			(ffa_id_t)args->arg1, (ffa_vcpu_count_t)args->arg2,
			current);
		return true;
	case FFA_NOTIFICATION_BITMAP_DESTROY_32:
		*args = api_ffa_notification_bitmap_destroy(
			(ffa_id_t)args->arg1, current);
		return true;
	case FFA_NOTIFICATION_BIND_32:
		*args = api_ffa_notification_update_bindings(
			ffa_sender(*args), ffa_receiver(*args), args->arg2,
			ffa_notifications_bitmap(args->arg3, args->arg4), true,
			current);
		return true;
	case FFA_NOTIFICATION_UNBIND_32:
		*args = api_ffa_notification_update_bindings(
			ffa_sender(*args), ffa_receiver(*args), 0,
			ffa_notifications_bitmap(args->arg3, args->arg4), false,
			current);
		return true;
	case FFA_MEM_PERM_SET_32:
	case FFA_MEM_PERM_SET_64:
		*args = api_ffa_mem_perm_set(va_init(args->arg1), args->arg2,
					     args->arg3, current);
		return true;
	case FFA_MEM_PERM_GET_32:
	case FFA_MEM_PERM_GET_64:
		*args = api_ffa_mem_perm_get(va_init(args->arg1), current);
		return true;
	case FFA_NOTIFICATION_SET_32:
		*args = api_ffa_notification_set(
			ffa_sender(*args), ffa_receiver(*args), args->arg2,
			ffa_notifications_bitmap(args->arg3, args->arg4),
			current);
		return true;
	case FFA_NOTIFICATION_GET_32:
		*args = api_ffa_notification_get(
			ffa_receiver(*args), ffa_notifications_get_vcpu(*args),
			args->arg2, current);
		return true;
	case FFA_NOTIFICATION_INFO_GET_64:
		*args = api_ffa_notification_info_get(current);
		return true;
	case FFA_INTERRUPT_32:
		/*
		 * A malicious SP could invoke a HVC/SMC call with
		 * FFA_INTERRUPT_32 as the function argument. Return error to
		 * avoid DoS.
		 */
		if (current->vm->id != HF_OTHER_WORLD_ID) {
			*args = ffa_error(FFA_DENIED);
			return true;
		}

		plat_ffa_handle_secure_interrupt(current, next);

		/*
		 * If the next vCPU belongs to an SP, the next time the NWd
		 * gets resumed these values will be overwritten by the ABI
		 * that used to handover execution back to the NWd.
		 * If the NWd is to be resumed from here, then it will
		 * receive the FFA_NORMAL_WORLD_RESUME ABI which is to signal
		 * that an interrupt has occured, thought it wasn't handled.
		 * This happens when the target vCPU was in preempted state,
		 * and the SP couldn't not be resumed to handle the interrupt.
		 */
		*args = (struct ffa_value){.func = FFA_NORMAL_WORLD_RESUME};
		return true;
	case FFA_CONSOLE_LOG_32:
	case FFA_CONSOLE_LOG_64:
		*args = api_ffa_console_log(*args, current);
		return true;
	case FFA_ERROR_32:
		*args = plat_ffa_error_32(current, next, args->arg2);
		return true;

	default:
		return false;
	}
}

/**
 * Set or clear VI/VF bits according to pending interrupts.
 * If `vcpu` is NULL, the function will set it to the currently running
 * vCPU.
 */
static void vcpu_update_virtual_interrupts(struct vcpu *vcpu)
{
	struct vcpu_locked vcpu_locked;

	if (vcpu == NULL) {
		vcpu = current();
	}

	/* Only update to those at the virtual instance. */
	if (vcpu->vm->el0_partition || !vm_id_is_current_world(vcpu->vm->id)) {
		return;
	}

	vcpu_locked = vcpu_lock(vcpu);
	set_virtual_irq(&vcpu->regs,
			vcpu_interrupt_irq_count_get(vcpu_locked) > 0);
	set_virtual_fiq(&vcpu->regs,
			vcpu_interrupt_fiq_count_get(vcpu_locked) > 0);
	vcpu_unlock(&vcpu_locked);
}

/**
 * Handles PSCI and FF-A calls and writes the return value back to the registers
 * of the vCPU. This is shared between smc_handler and hvc_handler.
 *
 * Returns true if the call was handled.
 */
static bool hvc_smc_handler(struct ffa_value args, struct vcpu *vcpu,
			    struct vcpu **next)
{
	const uint32_t func = args.func;

	/* Do not expect PSCI calls emitted from within the secure world. */
#if SECURE_WORLD == 0
	if (psci_handler(vcpu, func, args.arg1, args.arg2, args.arg3,
			 &vcpu->regs.r[0], next)) {
		return true;
	}
#endif

	if (ffa_handler(&args, vcpu, next)) {
#if SECURE_WORLD == 1
		/*
		 * If giving back execution to the NWd, check if the Schedule
		 * Receiver Interrupt has been delayed, and trigger it on
		 * current core if so.
		 */
		if ((*next != NULL && (*next)->vm->id == HF_OTHER_WORLD_ID) ||
		    (*next == NULL && vcpu->vm->id == HF_OTHER_WORLD_ID)) {
			plat_ffa_sri_trigger_if_delayed(vcpu->cpu);
		}
#endif
		if (func != FFA_VERSION_32) {
			struct vm_locked vm_locked = vm_lock(vcpu->vm);

			vm_locked.vm->ffa_version_negotiated = true;
			vm_unlock(&vm_locked);
		}

		arch_regs_set_retval(&vcpu->regs, args);

		/*
		 * In case there has been an update after handling the last
		 * ff-a call, update the next vCPU directly in the
		 * register.
		 */
		vcpu_update_virtual_interrupts(*next);
		return true;
	}

	return false;
}

/**
 * Processes SMC instruction calls.
 */
static struct vcpu *smc_handler(struct vcpu *vcpu)
{
	struct ffa_value args = arch_regs_get_args(&vcpu->regs);
	struct vcpu *next = NULL;

	/* Mask out SMCCC SVE hint bit from function id. */
	args.func &= ~SMCCC_SVE_HINT_MASK;

	if (hvc_smc_handler(args, vcpu, &next)) {
		return next;
	}

	smc_forwarder(vcpu->vm, &args);
	arch_regs_set_retval(&vcpu->regs, args);
	return NULL;
}

#if SECURE_WORLD == 1

/**
 * Called from other_world_loop return from SMC.
 * Processes SMC calls originating from the NWd.
 */
struct vcpu *smc_handler_from_nwd(struct vcpu *vcpu)
{
	struct ffa_value args = arch_regs_get_args(&vcpu->regs);
	struct vcpu *next = NULL;

	plat_save_ns_simd_context(vcpu);

	/* Mask out SMCCC SVE hint bit from function id. */
	args.func &= ~SMCCC_SVE_HINT_MASK;

	if (hvc_smc_handler(args, vcpu, &next)) {
		return next;
	}

	/*
	 * If the SMC emitted by the normal world is not handled in the secure
	 * world then return an error stating such ABI is not supported. Only
	 * FF-A calls are supported. We cannot return SMCCC_ERROR_UNKNOWN
	 * directly because the SPMD smc handler would not recognize it as a
	 * standard FF-A call returning from the SPMC.
	 */
	arch_regs_set_retval(&vcpu->regs, ffa_error(FFA_NOT_SUPPORTED));

	return NULL;
}

#endif

/*
 * Exception vector offsets.
 * See Arm Architecture Reference Manual Armv8-A, D1.10.2.
 */

/**
 * Offset for synchronous exceptions at current EL with SPx.
 */
#define OFFSET_CURRENT_SPX UINT64_C(0x200)

/**
 * Offset for synchronous exceptions at lower EL using AArch64.
 */
#define OFFSET_LOWER_EL_64 UINT64_C(0x400)

/**
 * Offset for synchronous exceptions at lower EL using AArch32.
 */
#define OFFSET_LOWER_EL_32 UINT64_C(0x600)

/**
 * Returns the address for the exception handler at EL1.
 */
static uintreg_t get_el1_exception_handler_addr(const struct vcpu *vcpu)
{
	uintreg_t base_addr = has_vhe_support() ? read_msr(MSR_VBAR_EL12)
						: read_msr(vbar_el1);
	uintreg_t pe_mode = vcpu->regs.spsr & PSR_PE_MODE_MASK;
	bool is_arch32 = vcpu->regs.spsr & PSR_ARCH_MODE_32;

	if (pe_mode == PSR_PE_MODE_EL0T) {
		if (is_arch32) {
			base_addr += OFFSET_LOWER_EL_32;
		} else {
			base_addr += OFFSET_LOWER_EL_64;
		}
	} else {
		CHECK(!is_arch32);
		base_addr += OFFSET_CURRENT_SPX;
	}

	return base_addr;
}

/**
 * Injects an exception with the specified Exception Syndrom Register value into
 * the EL1.
 *
 * NOTE: This function assumes that the lazy registers haven't been saved, and
 * writes to the lazy registers of the CPU directly instead of the vCPU.
 */
static void inject_el1_exception(struct vcpu *vcpu, uintreg_t esr_el1_value,
				 uintreg_t far_el1_value)
{
	uintreg_t handler_address = get_el1_exception_handler_addr(vcpu);

	/* Update the CPU state to inject the exception. */
	if (has_vhe_support()) {
		write_msr(MSR_ESR_EL12, esr_el1_value);
		write_msr(MSR_FAR_EL12, far_el1_value);
		write_msr(MSR_ELR_EL12, vcpu->regs.pc);
		write_msr(MSR_SPSR_EL12, vcpu->regs.spsr);
	} else {
		write_msr(esr_el1, esr_el1_value);
		write_msr(far_el1, far_el1_value);
		write_msr(elr_el1, vcpu->regs.pc);
		write_msr(spsr_el1, vcpu->regs.spsr);
	}

	/*
	 * Mask (disable) interrupts and run in EL1h mode.
	 * EL1h mode is used because by default, taking an exception selects the
	 * stack pointer for the target Exception level. The software can change
	 * that later in the handler if needed.
	 */
	vcpu->regs.spsr = PSR_D | PSR_A | PSR_I | PSR_F | PSR_PE_MODE_EL1H;

	/* Transfer control to the exception hander. */
	vcpu->regs.pc = handler_address;
}

/**
 * Injects a Data Abort exception (same exception level).
 */
static void inject_el1_data_abort_exception(struct vcpu *vcpu,
					    uintreg_t esr_el2,
					    uintreg_t far_el2)
{
	/*
	 *  ISS encoding remains the same, but the EC is changed to reflect
	 *  where the exception came from.
	 *  See Arm Architecture Reference Manual Armv8-A, pages D13-2943/2982.
	 */
	uintreg_t esr_el1_value = GET_ESR_ISS(esr_el2) | GET_ESR_IL(esr_el2) |
				  (EC_DATA_ABORT_SAME_EL << ESR_EC_OFFSET);

	dlog_notice("Injecting Data Abort exception into VM %#x.\n",
		    vcpu->vm->id);

	inject_el1_exception(vcpu, esr_el1_value, far_el2);
}

/**
 * Injects a Data Abort exception (same exception level).
 */
static void inject_el1_instruction_abort_exception(struct vcpu *vcpu,
						   uintreg_t esr_el2,
						   uintreg_t far_el2)
{
	/*
	 *  ISS encoding remains the same, but the EC is changed to reflect
	 *  where the exception came from.
	 *  See Arm Architecture Reference Manual Armv8-A, pages D13-2941/2980.
	 */
	uintreg_t esr_el1_value =
		GET_ESR_ISS(esr_el2) | GET_ESR_IL(esr_el2) |
		(EC_INSTRUCTION_ABORT_SAME_EL << ESR_EC_OFFSET);

	dlog_notice("Injecting Instruction Abort exception into VM %#x.\n",
		    vcpu->vm->id);

	inject_el1_exception(vcpu, esr_el1_value, far_el2);
}

/**
 * Injects an exception with an unknown reason into the EL1.
 */
static void inject_el1_unknown_exception(struct vcpu *vcpu, uintreg_t esr_el2)
{
	uintreg_t esr_el1_value =
		GET_ESR_IL(esr_el2) | (EC_UNKNOWN << ESR_EC_OFFSET);

	dlog_notice("Injecting Unknown Reason exception into VM %#x.\n",
		    vcpu->vm->id);

	/*
	 * The value of the far_el2 register is UNKNOWN in this case,
	 * therefore, don't propagate it to avoid leaking sensitive information.
	 */
	inject_el1_exception(vcpu, esr_el1_value, 0);
}

/**
 * Injects an exception because of a system register trap.
 */
static void inject_el1_sysreg_trap_exception(struct vcpu *vcpu,
					     uintreg_t esr_el2)
{
	char *direction_str = ISS_IS_READ(esr_el2) ? "read" : "write";

	dlog_notice(
		"Trapped access to system register %s: op0=%lu, op1=%lu, "
		"crn=%lu, "
		"crm=%lu, op2=%lu, rt=%lu.\n",
		direction_str, GET_ISS_OP0(esr_el2), GET_ISS_OP1(esr_el2),
		GET_ISS_CRN(esr_el2), GET_ISS_CRM(esr_el2),
		GET_ISS_OP2(esr_el2), GET_ISS_RT(esr_el2));

	inject_el1_unknown_exception(vcpu, esr_el2);
}

static struct vcpu *hvc_handler(struct vcpu *vcpu)
{
	struct ffa_value args = arch_regs_get_args(&vcpu->regs);
	struct vcpu *next = NULL;

	/* Mask out SMCCC SVE hint bit from function id. */
	args.func &= ~SMCCC_SVE_HINT_MASK;

	if (hvc_smc_handler(args, vcpu, &next)) {
		return next;
	}

	switch (args.func) {
#if SECURE_WORLD == 1
	case HF_INTERRUPT_DEACTIVATE:
		vcpu->regs.r[0] = plat_ffa_interrupt_deactivate(
			args.arg1, args.arg2, vcpu);
		break;

	case HF_INTERRUPT_RECONFIGURE:
		vcpu->regs.r[0] = plat_ffa_interrupt_reconfigure(
			args.arg1, args.arg2, args.arg3, vcpu);
		break;

	case HF_INTERRUPT_SEND_IPI:
		vcpu->regs.r[0] = api_hf_interrupt_send_ipi(args.arg1, vcpu);
		break;
#endif
	case HF_INTERRUPT_ENABLE:
		vcpu->regs.r[0] = api_interrupt_enable(args.arg1, args.arg2,
						       args.arg3, vcpu);
		break;

	case HF_INTERRUPT_GET: {
		struct vcpu_locked current_locked;

		current_locked = vcpu_lock(vcpu);
		vcpu->regs.r[0] = plat_ffa_interrupt_get(current_locked);
		vcpu_unlock(&current_locked);
		break;
	}
	default:
		vcpu->regs.r[0] = SMCCC_ERROR_UNKNOWN;
		dlog_verbose("Unsupported function %#lx\n", args.func);
	}

	/*
	 * In case there has been an update after handling the last
	 * hypervisor call, update the next vCPU directly in the register.
	 */
	vcpu_update_virtual_interrupts(next);

	return next;
}

struct vcpu *irq_lower(void)
{
#if SECURE_WORLD == 1
	struct vcpu *next = NULL;

	plat_ffa_handle_secure_interrupt(current(), &next);

	/*
	 * Since we are in interrupt context, set the bit for the
	 * next vCPU directly in the register.
	 */
	vcpu_update_virtual_interrupts(next);

	return next;
#else
	/*
	 * Switch back to primary VM, interrupts will be handled there.
	 *
	 * If the VM has aborted, this vCPU will be aborted when the scheduler
	 * tries to run it again. This means the interrupt will not be delayed
	 * by the aborted VM.
	 *
	 * TODO: Only switch when the interrupt isn't for the current VM.
	 */
	return api_preempt(current());
#endif
}

#if SECURE_WORLD == 1
static void spmd_group0_intr_delegate(void)
{
	struct ffa_value ret;

	dlog_verbose("Delegating Group0 interrupt to SPMD\n");

	ret = smc_ffa_call((struct ffa_value){.func = FFA_EL3_INTR_HANDLE_32});

	/* Check if the Group0 interrupt was handled successfully. */
	CHECK(ret.func == FFA_SUCCESS_32);
}
#endif

struct vcpu *fiq_lower(void)
{
#if SECURE_WORLD == 1
	struct vcpu_locked current_locked;
	struct vcpu *current_vcpu = current();
	int64_t ret;
	uint32_t intid;

	intid = get_highest_pending_g0_interrupt_id();

	/* Check for the highest priority pending Group0 interrupt. */
	if (intid != SPURIOUS_INTID_OTHER_WORLD) {
		/* Delegate handling of Group0 interrupt to EL3 firmware. */
		spmd_group0_intr_delegate();

		/* Resume current vCPU. */
		return NULL;
	}

	/*
	 * A special interrupt indicating there is no pending interrupt
	 * with sufficient priority for current security state. This
	 * means a non-secure interrupt is pending.
	 */
	assert(current_vcpu->vm->ns_interrupts_action != NS_ACTION_QUEUED);

	if (plat_ffa_vm_managed_exit_supported(current_vcpu->vm)) {
		uint8_t pmr = plat_interrupts_get_priority_mask();

		/*
		 * Mask non-secure interrupt from triggering again till the
		 * vCPU completes the managed exit sequenece.
		 */
		plat_interrupts_set_priority_mask(SWD_MASK_NS_INT);

		current_locked = vcpu_lock(current_vcpu);
		current_vcpu->prev_interrupt_priority = pmr;
		ret = api_interrupt_inject_locked(current_locked,
						  HF_MANAGED_EXIT_INTID,
						  current_locked, NULL);
		if (ret != 0) {
			panic("Failed to inject managed exit interrupt\n");
		}

		/* Entering managed exit sequence. */
		current_vcpu->processing_managed_exit = true;

		vcpu_unlock(&current_locked);

		/*
		 * Since we are in interrupt context, set the bit for the
		 * current vCPU directly in the register.
		 */
		vcpu_update_virtual_interrupts(NULL);

		/* Resume current vCPU. */
		return NULL;
	}

	/*
	 * Unwind Normal World Scheduled Call chain in response to NS
	 * Interrupt.
	 */
	return plat_ffa_unwind_nwd_call_chain_interrupt(current_vcpu);
#else
	return irq_lower();
#endif
}

noreturn struct vcpu *serr_lower(void)
{
	/*
	 * SError exceptions should be isolated and handled by the responsible
	 * VM/exception level. Getting here indicates a bug, that isolation is
	 * not working, or a processor that does not support ARMv8.2-IESB, in
	 * which case Hafnium routes SError exceptions to EL2 (here).
	 */
	panic("SError from a lower exception level.");
}

/**
 * Initialises a fault info structure. It assumes that an FnV bit exists at
 * bit offset 10 of the ESR, and that it is only valid when the bottom 6 bits of
 * the ESR (the fault status code) are 010000; this is the case for both
 * instruction and data aborts, but not necessarily for other exception reasons.
 */
static struct vcpu_fault_info fault_info_init(uintreg_t esr,
					      const struct vcpu *vcpu,
					      uint32_t mode)
{
	uint32_t fsc = esr & 0x3f;
	struct vcpu_fault_info r;
	uint64_t hpfar_el2_val;
	uint64_t hpfar_el2_fipa;

	r.mode = mode;
	r.pc = va_init(vcpu->regs.pc);

	/* Get Hypervisor IPA Fault Address value. */
	hpfar_el2_val = read_msr(hpfar_el2);

	/* Extract Faulting IPA. */
	hpfar_el2_fipa = (hpfar_el2_val & HPFAR_EL2_FIPA) << 8;

#if SECURE_WORLD == 1

	/**
	 * Determine if faulting IPA targets NS space.
	 * At NS-EL2 hpfar_el2 bit 63 is RES0. At S-EL2, this bit determines if
	 * the faulting Stage-1 address output is a secure or non-secure IPA.
	 */
	if ((hpfar_el2_val & HPFAR_EL2_NS) != 0) {
		r.mode |= MM_MODE_NS;
	}

#endif

	/*
	 * Check the FnV bit, which is only valid if dfsc/ifsc is 010000. It
	 * indicates that we cannot rely on far_el2.
	 */
	if (fsc == 0x10 && GET_ESR_FNV(esr)) {
		r.vaddr = va_init(0);
		r.ipaddr = ipa_init(hpfar_el2_fipa);
	} else {
		r.vaddr = va_init(read_msr(far_el2));
		r.ipaddr = ipa_init(hpfar_el2_fipa |
				    (read_msr(far_el2) & (PAGE_SIZE - 1)));
	}

	return r;
}

struct vcpu *sync_lower_exception(uintreg_t esr, uintreg_t far)
{
	struct vcpu *vcpu = current();
	struct vcpu_fault_info info;
	struct vcpu *new_vcpu = NULL;
	uintreg_t ec = GET_ESR_EC(esr);
	bool is_el0_partition = vcpu->vm->el0_partition;
	bool resume = false;

	switch (ec) {
	case EC_WFI_WFE:
		/* Skip the instruction. */
		vcpu->regs.pc += GET_NEXT_PC_INC(esr);

		/*
		 * For EL0 partitions, treat both WFI and WFE the same way so
		 * that FFA_RUN can be called on the partition to resume it. If
		 * we treat WFI using api_wait_for_interrupt, the VCPU will be
		 * in blocked waiting for interrupt but we cannot inject
		 * interrupts into EL0 partitions.
		 */
		if (is_el0_partition) {
			api_yield(vcpu, &new_vcpu, NULL);
			return new_vcpu;
		}

		/* Check TI bit of ISS, 0 = WFI, 1 = WFE. */
		if (esr & 1) {
			/* WFE */
			/*
			 * TODO: consider giving the scheduler more context,
			 * somehow.
			 */
			api_yield(vcpu, &new_vcpu, NULL);
			return new_vcpu;
		}
		/* WFI */
		return api_wait_for_interrupt(vcpu);

	case EC_DATA_ABORT_LOWER_EL:
		info = fault_info_init(
			esr, vcpu, (esr & (1U << 6)) ? MM_MODE_W : MM_MODE_R);

		resume = vcpu_handle_page_fault(vcpu, &info);
		if (is_el0_partition) {
			dlog_warning("Data abort on EL0 partition\n");
			/*
			 * Abort EL0 context if we should not resume the
			 * context, or it is an alignment fault.
			 * vcpu_handle_page_fault() only checks the mode of the
			 * page in an architecture agnostic way but alignment
			 * faults on aarch64 can happen on a correctly mapped
			 * page.
			 */
			if (!resume || ((esr & 0x3f) == 0x21)) {
				return api_abort(vcpu);
			}
		}

		if (resume) {
			return NULL;
		}

		/* Inform the EL1 of the data abort. */
		inject_el1_data_abort_exception(vcpu, esr, far);

		/* Schedule the same VM to continue running. */
		return NULL;

	case EC_INSTRUCTION_ABORT_LOWER_EL:
		info = fault_info_init(esr, vcpu, MM_MODE_X);

		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}

		if (is_el0_partition) {
			dlog_warning("Instruction abort on EL0 partition\n");
			return api_abort(vcpu);
		}

		/* Inform the EL1 of the instruction abort. */
		inject_el1_instruction_abort_exception(vcpu, esr, far);

		/* Schedule the same VM to continue running. */
		return NULL;
	case EC_SVC:
		CHECK(is_el0_partition);
		return hvc_handler(vcpu);
	case EC_HVC:
		if (is_el0_partition) {
			dlog_warning("Unexpected HVC Trap on EL0 partition\n");
			return api_abort(vcpu);
		}
		return hvc_handler(vcpu);

	case EC_SMC: {
		uintreg_t smc_pc = vcpu->regs.pc;
		struct vcpu *next = smc_handler(vcpu);

		/* Skip the SMC instruction. */
		vcpu->regs.pc = smc_pc + GET_NEXT_PC_INC(esr);

		return next;
	}

	case EC_MSR:
		/*
		 * NOTE: This should never be reached because it goes through a
		 * separate path handled by handle_system_register_access().
		 */
		panic("Handled by handle_system_register_access().");

	default:
		dlog_notice(
			"Unknown lower sync exception pc=%#lx, esr=%#lx, "
			"ec=%#lx\n",
			vcpu->regs.pc, esr, ec);
		break;
	}

	if (is_el0_partition) {
		return api_abort(vcpu);
	}

	/*
	 * The exception wasn't handled. Inject to the VM to give it chance to
	 * handle as an unknown exception.
	 */
	inject_el1_unknown_exception(vcpu, esr);

	/* Schedule the same VM to continue running. */
	return NULL;
}

/**
 * Handles EC = 011000, MSR, MRS instruction traps.
 * Returns non-null ONLY if the access failed and the vCPU is changing.
 */
void handle_system_register_access(uintreg_t esr_el2)
{
	struct vcpu *vcpu = current();
	ffa_id_t vm_id = vcpu->vm->id;
	uintreg_t ec = GET_ESR_EC(esr_el2);

	CHECK(ec == EC_MSR);
	/*
	 * Handle accesses to debug and performance monitor registers.
	 * Inject an exception for unhandled/unsupported registers.
	 */
	if (debug_el1_is_register_access(esr_el2)) {
		if (!debug_el1_process_access(vcpu, vm_id, esr_el2)) {
			inject_el1_sysreg_trap_exception(vcpu, esr_el2);
			return;
		}
	} else if (perfmon_is_register_access(esr_el2)) {
		if (!perfmon_process_access(vcpu, vm_id, esr_el2)) {
			inject_el1_sysreg_trap_exception(vcpu, esr_el2);
			return;
		}
	} else if (feature_id_is_register_access(esr_el2)) {
		if (!feature_id_process_access(vcpu, esr_el2)) {
			inject_el1_sysreg_trap_exception(vcpu, esr_el2);
			return;
		}
	} else if (el1_physical_timer_is_register_access(esr_el2)) {
		if (!el1_physical_timer_process_access(vcpu, esr_el2)) {
			inject_el1_sysreg_trap_exception(vcpu, esr_el2);
			return;
		}
	} else {
		inject_el1_sysreg_trap_exception(vcpu, esr_el2);
		return;
	}

	/* Instruction was fulfilled. Skip it and run the next one. */
	vcpu->regs.pc += GET_NEXT_PC_INC(esr_el2);
}
