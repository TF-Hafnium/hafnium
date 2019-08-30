/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdnoreturn.h>

#include "hf/arch/barriers.h"
#include "hf/arch/init.h"
#include "hf/arch/mm.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/panic.h"
#include "hf/spci.h"
#include "hf/vm.h"

#include "vmapi/hf/call.h"

#include "debug_el1.h"
#include "msr.h"
#include "perfmon.h"
#include "psci.h"
#include "psci_handler.h"
#include "smc.h"
#include "sysregs.h"

/**
 * Gets the Exception Class from the ESR.
 */
#define GET_ESR_EC(esr) ((esr) >> 26)

/**
 * Gets the Instruction Length bit for the synchronous exception
 */
#define GET_ESR_IL(esr) ((esr) & (1 << 25))

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
 * Returns a reference to the currently executing vCPU.
 */
static struct vcpu *current(void)
{
	return (struct vcpu *)read_msr(tpidr_el2);
}

/**
 * Saves the state of per-vCPU peripherals, such as the virtual timer, and
 * informs the arch-independent sections that registers have been saved.
 */
void complete_saving_state(struct vcpu *vcpu)
{
	vcpu->regs.peripherals.cntv_cval_el0 = read_msr(cntv_cval_el0);
	vcpu->regs.peripherals.cntv_ctl_el0 = read_msr(cntv_ctl_el0);

	api_regs_state_saved(vcpu);

	/*
	 * If switching away from the primary, copy the current EL0 virtual
	 * timer registers to the corresponding EL2 physical timer registers.
	 * This is used to emulate the virtual timer for the primary in case it
	 * should fire while the secondary is running.
	 */
	if (vcpu->vm->id == HF_PRIMARY_VM_ID) {
		/*
		 * Clear timer control register before copying compare value, to
		 * avoid a spurious timer interrupt. This could be a problem if
		 * the interrupt is configured as edge-triggered, as it would
		 * then be latched in.
		 */
		write_msr(cnthp_ctl_el2, 0);
		write_msr(cnthp_cval_el2, read_msr(cntv_cval_el0));
		write_msr(cnthp_ctl_el2, read_msr(cntv_ctl_el0));
	}
}

/**
 * Restores the state of per-vCPU peripherals, such as the virtual timer.
 */
void begin_restoring_state(struct vcpu *vcpu)
{
	/*
	 * Clear timer control register before restoring compare value, to avoid
	 * a spurious timer interrupt. This could be a problem if the interrupt
	 * is configured as edge-triggered, as it would then be latched in.
	 */
	write_msr(cntv_ctl_el0, 0);
	write_msr(cntv_cval_el0, vcpu->regs.peripherals.cntv_cval_el0);
	write_msr(cntv_ctl_el0, vcpu->regs.peripherals.cntv_ctl_el0);

	/*
	 * If we are switching (back) to the primary, disable the EL2 physical
	 * timer which was being used to emulate the EL0 virtual timer, as the
	 * virtual timer is now running for the primary again.
	 */
	if (vcpu->vm->id == HF_PRIMARY_VM_ID) {
		write_msr(cnthp_ctl_el2, 0);
		write_msr(cnthp_cval_el2, 0);
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

	__asm__ volatile("tlbi vmalle1");

	/*
	 * Ensure that no instructions are fetched for the VM until after the
	 * TLB invalidation has taken effect.
	 */
	isb();

	/*
	 * Ensure that no data reads or writes for the VM happen until after the
	 * TLB invalidation has taken effect. Non-sharable is enough because the
	 * TLB is local to the CPU.
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
	spci_vcpu_index_t new_vcpu_index = vcpu_index(vcpu);

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

noreturn void irq_current_exception(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("IRQ from current");
}

noreturn void fiq_current_exception(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("FIQ from current");
}

noreturn void serr_current_exception(uintreg_t elr, uintreg_t spsr)
{
	(void)elr;
	(void)spsr;

	panic("SERR from current");
}

noreturn void sync_current_exception(uintreg_t elr, uintreg_t spsr)
{
	uintreg_t esr = read_msr(esr_el2);
	uintreg_t ec = GET_ESR_EC(esr);

	(void)spsr;

	switch (ec) {
	case 0x25: /* EC = 100101, Data abort. */
		dlog("Data abort: pc=%#x, esr=%#x, ec=%#x", elr, esr, ec);
		if (!(esr & (1U << 10))) { /* Check FnV bit. */
			dlog(", far=%#x", read_msr(far_el2));
		} else {
			dlog(", far=invalid");
		}

		dlog("\n");
		break;

	default:
		dlog("Unknown current sync exception pc=%#x, esr=%#x, "
		     "ec=%#x\n",
		     elr, esr, ec);
		break;
	}

	panic("EL2 exception");
}

/**
 * Sets or clears the VI bit in the HCR_EL2 register saved in the given
 * arch_regs.
 */
static void set_virtual_interrupt(struct arch_regs *r, bool enable)
{
	if (enable) {
		r->lazy.hcr_el2 |= HCR_EL2_VI;
	} else {
		r->lazy.hcr_el2 &= ~HCR_EL2_VI;
	}
}

/**
 * Sets or clears the VI bit in the HCR_EL2 register.
 */
static void set_virtual_interrupt_current(bool enable)
{
	uintreg_t hcr_el2 = read_msr(hcr_el2);

	if (enable) {
		hcr_el2 |= HCR_EL2_VI;
	} else {
		hcr_el2 &= ~HCR_EL2_VI;
	}
	write_msr(hcr_el2, hcr_el2);
}

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

	dlog("SMC %#010x attempted from VM %d, blocked=%d\n", func, vm->id,
	     block_by_default);

	/* Access is still allowed in permissive mode. */
	return block_by_default;
}

/**
 * Applies SMC access control according to manifest and forwards the call if
 * access is granted.
 */
static void smc_forwarder(const struct vcpu *vcpu, struct spci_value *ret)
{
	uint32_t func = vcpu->regs.r[0];
	uint32_t client_id = vcpu->vm->id;
	uintreg_t arg7;

	if (smc_is_blocked(vcpu->vm, func)) {
		ret->func = SMCCC_ERROR_UNKNOWN;
		return;
	}

	/*
	 * Set the Client ID but keep the existing Secure OS ID and anything
	 * else (currently unspecified) that the client may have passed in the
	 * upper bits.
	 */
	arg7 = client_id | (vcpu->regs.r[7] & ~CLIENT_ID_MASK);
	*ret = smc_forward(func, vcpu->regs.r[1], vcpu->regs.r[2],
			   vcpu->regs.r[3], vcpu->regs.r[4], vcpu->regs.r[5],
			   vcpu->regs.r[6], arg7);

	/*
	 * Preserve the value passed by the caller, rather than the client_id we
	 * generated. Note that this would also overwrite any return value that
	 * may be in x7, but the SMCs that we are forwarding are legacy calls
	 * from before SMCCC 1.2 so won't have more than 4 return values anyway.
	 */
	ret->arg7 = vcpu->regs.r[7];
}

static bool spci_handler(struct spci_value *args, struct vcpu **next)
{
	/*
	 * NOTE: When adding new methods to this handler update
	 * api_spci_features accordingly.
	 */
	switch (args->func & ~SMCCC_CONVENTION_MASK) {
	case SPCI_VERSION_32:
		*args = api_spci_version();
		return true;
	case SPCI_ID_GET_32:
		*args = api_spci_id_get(current());
		return true;
	case SPCI_FEATURES_32:
		*args = api_spci_features(args->arg1);
		return true;
	case SPCI_RX_RELEASE_32:
		*args = api_spci_rx_release(current(), next);
		return true;
	case SPCI_RXTX_MAP_32:
		*args = api_spci_rxtx_map(ipa_init(args->arg1),
					  ipa_init(args->arg2), args->arg3,
					  current(), next);
		return true;
	case SPCI_YIELD_32:
		api_yield(current(), next);

		/* SPCI_YIELD always returns SPCI_SUCCESS. */
		*args = (struct spci_value){.func = SPCI_SUCCESS_32};

		return true;
	case SPCI_MSG_SEND_32:
		*args = api_spci_msg_send(spci_msg_send_sender(*args),
					  spci_msg_send_receiver(*args),
					  spci_msg_send_size(*args),
					  spci_msg_send_attributes(*args),
					  current(), next);
		return true;
	case SPCI_MSG_WAIT_32:
		*args = api_spci_msg_recv(true, current(), next);
		return true;
	case SPCI_MSG_POLL_32:
		*args = api_spci_msg_recv(false, current(), next);
		return true;
	case SPCI_RUN_32:
		*args = api_spci_run(spci_vm_id(*args), spci_vcpu_index(*args),
				     current(), next);
		return true;
	}

	return false;
}

/**
 * Set or clear VI bit according to pending interrupts.
 */
static void update_vi(struct vcpu *next)
{
	if (next == NULL) {
		/*
		 * Not switching vCPUs, set the bit for the current vCPU
		 * directly in the register.
		 */
		struct vcpu *vcpu = current();

		sl_lock(&vcpu->lock);
		set_virtual_interrupt_current(
			vcpu->interrupts.enabled_and_pending_count > 0);
		sl_unlock(&vcpu->lock);
	} else {
		/*
		 * About to switch vCPUs, set the bit for the vCPU to which we
		 * are switching in the saved copy of the register.
		 */
		sl_lock(&next->lock);
		set_virtual_interrupt(
			&next->regs,
			next->interrupts.enabled_and_pending_count > 0);
		sl_unlock(&next->lock);
	}
}

/**
 * Processes SMC instruction calls.
 */
static void smc_handler(struct vcpu *vcpu, struct spci_value *ret,
			struct vcpu **next)
{
	uint32_t func = vcpu->regs.r[0];

	if (psci_handler(vcpu, func, vcpu->regs.r[1], vcpu->regs.r[2],
			 vcpu->regs.r[3], &ret->func, next)) {
		return;
	}

	if (spci_handler(ret, next)) {
		update_vi(*next);
		return;
	}

	switch (func & ~SMCCC_CONVENTION_MASK) {
	case HF_DEBUG_LOG:
		ret->func = api_debug_log(vcpu->regs.r[1], vcpu);
		return;
	}

	smc_forwarder(vcpu, ret);
}

struct vcpu *hvc_handler(struct vcpu *vcpu)
{
	struct spci_value args = {
		.func = vcpu->regs.r[0],
		.arg1 = vcpu->regs.r[1],
		.arg2 = vcpu->regs.r[2],
		.arg3 = vcpu->regs.r[3],
		.arg4 = vcpu->regs.r[4],
		.arg5 = vcpu->regs.r[5],
		.arg6 = vcpu->regs.r[6],
		.arg7 = vcpu->regs.r[7],
	};
	struct vcpu *next = NULL;

	if (psci_handler(vcpu, args.func, args.arg1, args.arg2, args.arg3,
			 &vcpu->regs.r[0], &next)) {
		return next;
	}

	if (spci_handler(&args, &next)) {
		vcpu->regs.r[0] = args.func;
		vcpu->regs.r[1] = args.arg1;
		vcpu->regs.r[2] = args.arg2;
		vcpu->regs.r[3] = args.arg3;
		vcpu->regs.r[4] = args.arg4;
		vcpu->regs.r[5] = args.arg5;
		vcpu->regs.r[6] = args.arg6;
		vcpu->regs.r[7] = args.arg7;
		update_vi(next);
		return next;
	}

	switch (args.func) {
	case HF_VM_GET_COUNT:
		vcpu->regs.r[0] = api_vm_get_count();
		break;

	case HF_VCPU_GET_COUNT:
		vcpu->regs.r[0] = api_vcpu_get_count(args.arg1, vcpu);
		break;

	case HF_MAILBOX_WRITABLE_GET:
		vcpu->regs.r[0] = api_mailbox_writable_get(vcpu);
		break;

	case HF_MAILBOX_WAITER_GET:
		vcpu->regs.r[0] = api_mailbox_waiter_get(args.arg1, vcpu);
		break;

	case HF_INTERRUPT_ENABLE:
		vcpu->regs.r[0] =
			api_interrupt_enable(args.arg1, args.arg2, vcpu);
		break;

	case HF_INTERRUPT_GET:
		vcpu->regs.r[0] = api_interrupt_get(vcpu);
		break;

	case HF_INTERRUPT_INJECT:
		vcpu->regs.r[0] = api_interrupt_inject(args.arg1, args.arg2,
						       args.arg3, vcpu, &next);
		break;

	case HF_SHARE_MEMORY:
		vcpu->regs.r[0] = api_share_memory(
			args.arg1 >> 32, ipa_init(args.arg2), args.arg3,
			args.arg1 & 0xffffffff, vcpu);
		break;

	case HF_DEBUG_LOG:
		vcpu->regs.r[0] = api_debug_log(args.arg1, vcpu);
		break;

	default:
		vcpu->regs.r[0] = SMCCC_ERROR_UNKNOWN;
	}

	update_vi(next);

	return next;
}

struct vcpu *irq_lower(void)
{
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
}

struct vcpu *fiq_lower(void)
{
	return irq_lower();
}

struct vcpu *serr_lower(void)
{
	dlog("SERR from lower\n");
	return api_abort(current());
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

	r.mode = mode;
	r.pc = va_init(vcpu->regs.pc);

	/*
	 * Check the FnV bit, which is only valid if dfsc/ifsc is 010000. It
	 * indicates that we cannot rely on far_el2.
	 */
	if (fsc == 0x10 && esr & (1U << 10)) {
		r.vaddr = va_init(0);
		r.ipaddr = ipa_init(read_msr(hpfar_el2) << 8);
	} else {
		r.vaddr = va_init(read_msr(far_el2));
		r.ipaddr = ipa_init((read_msr(hpfar_el2) << 8) |
				    (read_msr(far_el2) & (PAGE_SIZE - 1)));
	}

	return r;
}

struct vcpu *sync_lower_exception(uintreg_t esr)
{
	struct vcpu *vcpu = current();
	struct vcpu_fault_info info;
	struct vcpu *new_vcpu;
	uintreg_t ec = GET_ESR_EC(esr);

	switch (ec) {
	case 0x01: /* EC = 000001, WFI or WFE. */
		/* Skip the instruction. */
		vcpu->regs.pc += GET_NEXT_PC_INC(esr);
		/* Check TI bit of ISS, 0 = WFI, 1 = WFE. */
		if (esr & 1) {
			/* WFE */
			/*
			 * TODO: consider giving the scheduler more context,
			 * somehow.
			 */
			api_yield(vcpu, &new_vcpu);
			return new_vcpu;
		}
		/* WFI */
		return api_wait_for_interrupt(vcpu);

	case 0x24: /* EC = 100100, Data abort. */
		info = fault_info_init(
			esr, vcpu, (esr & (1U << 6)) ? MM_MODE_W : MM_MODE_R);
		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}
		break;

	case 0x20: /* EC = 100000, Instruction abort. */
		info = fault_info_init(esr, vcpu, MM_MODE_X);
		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}
		break;

	case 0x16: /* EC = 010110, HVC instruction */
		return hvc_handler(vcpu);

	case 0x17: /* EC = 010111, SMC instruction. */ {
		uintreg_t smc_pc = vcpu->regs.pc;
		struct vcpu *next = NULL;
		struct spci_value ret = {.arg4 = vcpu->regs.r[4],
					 .arg5 = vcpu->regs.r[5],
					 .arg6 = vcpu->regs.r[6],
					 .arg7 = vcpu->regs.r[7]};

		smc_handler(vcpu, &ret, &next);

		/* Skip the SMC instruction. */
		vcpu->regs.pc = smc_pc + GET_NEXT_PC_INC(esr);
		vcpu->regs.r[0] = ret.func;
		vcpu->regs.r[1] = ret.arg1;
		vcpu->regs.r[2] = ret.arg2;
		vcpu->regs.r[3] = ret.arg3;
		vcpu->regs.r[4] = ret.arg4;
		vcpu->regs.r[5] = ret.arg5;
		vcpu->regs.r[6] = ret.arg6;
		vcpu->regs.r[7] = ret.arg7;
		return next;
	}

	/*
	 * EC = 011000, MSR, MRS or System instruction execution that is not
	 * reported using EC 000000, 000001 or 000111.
	 */
	case 0x18:
		/*
		 * NOTE: This should never be reached because it goes through a
		 * separate path handled by handle_system_register_access().
		 */
		panic("Handled by handle_system_register_access().");

	default:
		dlog("Unknown lower sync exception pc=%#x, esr=%#x, "
		     "ec=%#x\n",
		     vcpu->regs.pc, esr, ec);
		break;
	}

	/* The exception wasn't handled so abort the VM. */
	return api_abort(vcpu);
}

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
	uintreg_t base_addr = read_msr(vbar_el1);
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
 * Injects an exception with an unknown reason (EC=0x0) to the EL1.
 * See Arm Architecture Reference Manual Armv8-A, page D13-2924.
 *
 * NOTE: This function assumes that the lazy registers haven't been saved, and
 * writes to the lazy registers of the CPU directly instead of the vCPU.
 */
static struct vcpu *inject_el1_unknown_exception(struct vcpu *vcpu,
						 uintreg_t esr_el2)
{
	uintreg_t esr_el1_value = GET_ESR_IL(esr_el2);
	uintreg_t handler_address = get_el1_exception_handler_addr(vcpu);
	char *direction_str;

	/* Update the CPU state to inject the exception. */
	write_msr(esr_el1, esr_el1_value);
	write_msr(elr_el1, vcpu->regs.pc);
	write_msr(spsr_el1, vcpu->regs.spsr);

	/*
	 * Mask (disable) interrupts and run in EL1h mode.
	 * EL1h mode is used because by default, taking an exception selects the
	 * stack pointer for the target Exception level. The software can change
	 * that later in the handler if needed.
	 * See Arm Architecture Reference Manual Armv8-A, page D13-2924
	 */
	vcpu->regs.spsr = PSR_D | PSR_A | PSR_I | PSR_F | PSR_PE_MODE_EL1H;

	/* Transfer control to the exception hander. */
	vcpu->regs.pc = handler_address;

	direction_str = ISS_IS_READ(esr_el2) ? "read" : "write";
	dlog("Trapped access to system register %s: op0=%d, op1=%d, crn=%d, "
	     "crm=%d, op2=%d, rt=%d.\n",
	     direction_str, GET_ISS_OP0(esr_el2), GET_ISS_OP1(esr_el2),
	     GET_ISS_CRN(esr_el2), GET_ISS_CRM(esr_el2), GET_ISS_OP2(esr_el2),
	     GET_ISS_RT(esr_el2));

	dlog("Injecting Unknown Reason exception into VM%d.\n", vcpu->vm->id);
	dlog("Exception handler address 0x%x\n", handler_address);

	/* Schedule the same VM to continue running. */
	return NULL;
}

/**
 * Handles EC = 011000, msr, mrs instruction traps.
 * Returns non-null ONLY if the access failed and the vcpu is changing.
 */
struct vcpu *handle_system_register_access(uintreg_t esr_el2)
{
	struct vcpu *vcpu = current();
	spci_vm_id_t vm_id = vcpu->vm->id;
	uintreg_t ec = GET_ESR_EC(esr_el2);

	CHECK(ec == 0x18);
	/*
	 * Handle accesses to debug and performance monitor registers.
	 * Inject an exception for unhandled/unsupported registers.
	 */
	if (debug_el1_is_register_access(esr_el2)) {
		if (!debug_el1_process_access(vcpu, vm_id, esr_el2)) {
			return inject_el1_unknown_exception(vcpu, esr_el2);
		}
	} else if (perfmon_is_register_access(esr_el2)) {
		if (!perfmon_process_access(vcpu, vm_id, esr_el2)) {
			return inject_el1_unknown_exception(vcpu, esr_el2);
		}
	} else {
		return inject_el1_unknown_exception(vcpu, esr_el2);
	}

	/* Instruction was fulfilled. Skip it and run the next one. */
	vcpu->regs.pc += GET_NEXT_PC_INC(esr_el2);
	return NULL;
}
