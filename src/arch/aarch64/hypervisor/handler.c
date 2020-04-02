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
#include "hf/arch/plat/smc.h"

#include "hf/api.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/panic.h"
#include "hf/spci.h"
#include "hf/spci_internal.h"
#include "hf/vm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "debug_el1.h"
#include "feature_id.h"
#include "msr.h"
#include "perfmon.h"
#include "psci.h"
#include "psci_handler.h"
#include "smc.h"
#include "sysregs.h"

#include "hf/std.h"
/**
 * Gets the value to increment for the next PC.
 * The ESR encodes whether the instruction is 2 bytes or 4 bytes long.
 */
#define GET_NEXT_PC_INC(esr) (GET_ESR_IL(esr) ? 4 : 2)

/**
 * The Client ID field within X7 for an SMC64 call.
 */
#define CLIENT_ID_MASK UINT64_C(0xffff)

alignas(PAGE_SIZE) uint8_t hv_rx[4096];
alignas(PAGE_SIZE) uint8_t hv_tx[4096];
#if SECURE_WORLD == 1
struct spinlock rx_lock;
#else
struct spinlock tx_lock;
#endif

#if SECURE_WORLD == 1

struct hv_buffers_t hypervisor_buffers;

extern struct mpool api_page_pool;

bool handler_map_hv_buffers(uint8_t **tx, uint8_t **rx, paddr_t pa_send_begin,
			    paddr_t pa_send_end, paddr_t pa_recv_begin,
			    paddr_t pa_recv_end)
{
	struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();
	struct mpool local_page_pool;

	mpool_init_with_fallback(&local_page_pool, &api_page_pool);

	/* Map the send page as read-only in the hypervisor address space. */
	*tx = mm_identity_map(mm_stage1_locked, pa_send_begin, pa_send_end,
			      MM_MODE_R | MM_MODE_NS, &local_page_pool);

	*rx = mm_identity_map(mm_stage1_locked, pa_recv_begin, pa_recv_end,
			      MM_MODE_W | MM_MODE_NS, &local_page_pool);

	mm_unlock_stage1(&mm_stage1_locked);

	return true;
}
uint8_t *get_hv_tx()
{
       return hypervisor_buffers.tx;
}

uint8_t *get_hv_rx()
{
       return hypervisor_buffers.rx;
}

#else

uint8_t *get_hv_tx()
{
	return hv_tx;
}

uint8_t *get_hv_rx()
{
	return hv_rx;
}

void handler_register_normal_world_rxtx(void)
{
	smc32(SPCI_RXTX_MAP_64, (uintptr_t)hv_tx, (uintptr_t)hv_rx, 1, 0, 0, 0,
	      0);

	/* We should not care about the return from the secure world. */
}
#endif

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

noreturn void sync_current_exception_noreturn(uintreg_t elr, uintreg_t spsr)
{
	uintreg_t esr = read_msr(esr_el2);
	uintreg_t ec = GET_ESR_EC(esr);

	(void)spsr;

	switch (ec) {
	case EC_DATA_ABORT_SAME_EL:
		if (!(esr & (1U << 10))) { /* Check FnV bit. */
			dlog_error(
				"Data abort: pc=%#x, esr=%#x, ec=%#x, "
				"far=%#x\n",
				elr, esr, ec, read_msr(far_el2));
		} else {
			dlog_error(
				"Data abort: pc=%#x, esr=%#x, ec=%#x, "
				"far=invalid\n",
				elr, esr, ec);
		}

		break;

	default:
		dlog_error(
			"Unknown current sync exception pc=%#x, esr=%#x, "
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

	dlog_notice("SMC %#010x attempted from VM %d, blocked=%d\n", func,
		    vm->id, block_by_default);

	/* Access is still allowed in permissive mode. */
	return block_by_default;
}

/**
 * Applies SMC access control according to manifest and forwards the call if
 * access is granted.
 */
static void smc_forwarder(const struct vm *vm, struct spci_value *args)
{
	struct spci_value ret;
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

void spmd_exit64(struct spci_value *args)
{
	struct spci_value smc_res;

	/* Exit to SPMD */
	smc_res = smc64(args->func,
			args->arg1,
			args->arg2,
			args->arg3,
			args->arg4,
			args->arg5,
			args->arg6,
			args->arg7);

	/* Return from SPMD */
	*args = smc_res;
}
void spmd_exit(struct spci_value *args)
{
	struct spci_value smc_res;

	/* Exit to SPMD */
	smc_res = smc32(args->func,
			args->arg1,
			args->arg2,
			args->arg3,
			args->arg4,
			args->arg5,
			args->arg6,
			args->arg7);

	/* Return from SPMD */
	args->func = smc_res.func;
	args->arg1 = smc_res.arg1;
	args->arg2 = smc_res.arg2;
	args->arg3 = smc_res.arg3;
	args->arg4 = smc_res.arg4;
	args->arg5 = smc_res.arg5;
	args->arg6 = smc_res.arg6;
	args->arg7 = smc_res.arg7;
}

/* Helper function must be in arch/aarch64 because SECURE_WORLD is only defined for aarch64. */
__attribute((unused))static inline bool is_opposite_world_vm_id(spci_vm_id_t id)
{
#if SECURE_WORLD==1
	return (id & 0x8000)==0;
#else
	return (id & 0x8000)!=0;
#endif
}

struct spci_value spci_mem_op_resume_internal (uint32_t cookie,
	struct vm* from_vm);


/**
 * Discovery function returning information about partitions instantiated
 * in the system.
 */
struct spci_value api_spci_partition_info_get(struct vcpu *current,
					      uint32_t arg1, uint32_t arg2,
					      uint32_t arg3, uint32_t arg4, bool eret_origin)
{
	uint16_t index;
	uint16_t count = 0;
	#if !SECURE_WORLD
	uint16_t s_count = 0;
	#endif
	uint16_t vm_count = vm_get_count();
	struct vm *vm;
	struct vm *current_vm;

	uint32_t uuid[4] = {0};
	/* Reconstruct UUID. */
	uuid[0] = arg1;
	uuid[1] = arg2;
	uuid[2] = arg3;
	uuid[3] = arg4;

	/* Ensure we allocate enough storage space for both worlds. */
	struct spci_partition_info info[vm_count + MAX_VMS];

	for (index = 0; index < vm_count; index++) {
		#if SECURE_WORLD == 0
		vm = vm_find(index + HF_VM_ID_OFFSET);
		#else
		vm = vm_find((index + HF_VM_ID_OFFSET) | (SPMC_SECURE_ID_MASK << SPMC_SECURE_ID_SHIFT));
		#endif
		if (vm == NULL) {
			continue;
		}
		/*
		 * If NULL ID, return all partitions, otherwise only matching
		 * UUIDs.
		 */
		if ((!(uuid[0] || uuid[1] || uuid[2] || uuid[3])) ||
		    (uuid[0] == vm->uuid[0] && uuid[1] == vm->uuid[1] &&
		     uuid[2] == vm->uuid[2] && uuid[3] == vm->uuid[3])) {

			info[count].id = vm->id;
			info[count].execution_context = vm->vcpu_count;
			info[count].partition_properties = 0;

			switch (vm->messaging_method) {
			case SPCI_MESSAGING_METHOD_DIRECT:
				info[count].partition_properties |= 2;
				break;
			case SPCI_MESSAGING_METHOD_INDIRECT:
				info[count].partition_properties |= 4;
				break;
			case SPCI_MESSAGING_METHOD_BOTH:
				info[count].partition_properties |= 7;
				break;
			}
			count++;
		}
	}

#if SECURE_WORLD != 1
	bool secure_vms = false;

	/* Only check secure world if null or not found in normal world */
	if ((!(uuid[0] || uuid[1] || uuid[2] || uuid[3])) || !count){
		struct spci_value res;
		res = smc32(SPCI_PARTITION_INFO_GET_32, uuid[0], uuid[1], uuid[2],
		      uuid[3], 0, 0, 0);
		if (res.func == SPCI_SUCCESS_32){
			s_count = res.arg2;
			secure_vms = true;
		}
		else {
			return res;
		}

		/* Populate hypervisors buffer if results from secure world. */
		if (secure_vms) {
			/* TODO: Find out way to sync mailbox. */
			memcpy_s(&info[count],  sizeof(info), get_hv_rx(),
				 sizeof(struct spci_partition_info) * s_count);
			count = count + s_count;
		 }
		res = smc32(SPCI_RX_RELEASE_32, 0, 0, 0, 0, 0, 0, 0);
		if (res.func != SPCI_SUCCESS_32){
			panic("Could not release RX buffer\n");
		}
	}
#endif
	if (!count) {
		return spci_error(SPCI_INVALID_PARAMETERS);
	}

	/* Check if the mailbox is large enough to accommodate structs. */
	if (count * sizeof(struct spci_partition_info) > HF_MAILBOX_SIZE) {
		return spci_error(SPCI_NO_MEMORY);
	}

	if (!eret_origin) {
		if (current != NULL) {
			current_vm = current->vm;
		}
		else {
			return spci_error(SPCI_INVALID_PARAMETERS);
		}
		/* Call from partition. */
		sl_lock(&current_vm->lock);

		/* RX buffer is clear to populate. Reuse hafnium framework. */
		if (current_vm->mailbox.state == MAILBOX_STATE_EMPTY) {
			current_vm->mailbox.state = MAILBOX_STATE_RECEIVED;
			memcpy_s(current_vm->mailbox.recv, HF_MAILBOX_SIZE, &info,
				 sizeof(struct spci_partition_info) * count);
			current_vm->mailbox.recv_size =
				sizeof(struct spci_partition_info) * count;
			current_vm->mailbox.recv_sender = 0;
			//current_vm->mailbox.recv_attributes = 0;

		} else {
			sl_unlock(&current_vm->lock);
			return spci_error(SPCI_BUSY);
		}

		sl_unlock(&current_vm->lock);
	}
	else {
		#if SECURE_WORLD == 0
		/*Call from Hypervisor */
		panic("Invocation of PARTITION_INFO_GET not supported from HYP!\n");
		#else
		sl_lock(&rx_lock);
		memcpy_s(get_hv_rx(), HF_MAILBOX_SIZE, &info,
				 sizeof(struct spci_partition_info) * count);
		#endif
	}
	struct spci_value ret = {.func = SPCI_SUCCESS_32, .arg2 = count};
	return ret;
}

static bool spci_handler(struct spci_value *args, struct vcpu **next)
{
	__attribute((unused))struct spci_value smc_res;
	bool eret_origin = false;

	while (true) {
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
		{
			struct spci_value orig_args;
			orig_args.func = args->func;
			orig_args.arg1 = args->arg1;

			*args = api_spci_features(args->arg1);
			/* If call originated in the current world. */
			if (!eret_origin) {
				/* If supported in this wld check if other supports. */
				if (args->func == SPCI_SUCCESS_32){
					smc_res = smc32(orig_args.func, orig_args.arg1,
									0, 0, 0, 0, 0, 0);

					/* TODO: Make this less restrictive. */
					/* If current wld supports but not other, return Unsupported. */
					if (smc_res.func == SPCI_NOT_SUPPORTED) {
						args->func = smc_res.func;
						args->arg2 = 0;
					}
					else {
						/* If feature is supported take LCD of sub features. */
						args->arg2 &= smc_res.arg2;
					}
				}
			}
			else {
				/* Return to other world */
				spmd_exit(args);
				eret_origin = true;
				break;
			}
			return true;
		}
		case SPCI_RX_RELEASE_32:
		#if SECURE_WORLD == 1
			if (eret_origin) {
				/* TODO: Check if we have lock? */
				sl_unlock(&rx_lock);
				/* Return to Normal world */
				*args = (struct spci_value){.func = SPCI_SUCCESS_32};
				spmd_exit(args);
				eret_origin = true;
				break;
			}
			else {
				*args = api_spci_rx_release(current(), next);
				return true;
			}
		#else
			*args = api_spci_rx_release(current(), next);
			return true;
		#endif
		case SPCI_RXTX_MAP_32:
		case SPCI_RXTX_MAP_64:

#if SECURE_WORLD == 1
			if (eret_origin) {
				paddr_t pa_send_begin = pa_init(args->arg1);
				paddr_t pa_send_end =
					pa_init(args->arg1 + 4096);

				paddr_t pa_recv_begin = pa_init(args->arg2);
				paddr_t pa_recv_end =
					pa_init(args->arg2 + 4096);

				/*
				 * SPCI_RXTX_MAP originated in the normal world
				 * and hence must be from the Hypervisor.
				 */

				/*
				 * TODO: Remove assumption on this being a call
				 * from the Normal world Hv to register its own
				 * Rx Tx buffers.
				 */

				handler_map_hv_buffers(
					&hypervisor_buffers.tx,
					&hypervisor_buffers.rx, pa_send_begin,
					pa_send_end, pa_recv_begin,
					pa_recv_end);

				/* Return to Normal world */
				*args = (struct spci_value){.func = SPCI_SUCCESS_32};
				spmd_exit(args);

				eret_origin = true;
				break;
			}
#else
			/*
			 * TODO: The Normal World Hv must forward the
			 * SPCI_RXTX_MAP calls from its managed VMs to the
			 * Secure World.
			 */
#endif
			*args = api_spci_rxtx_map(ipa_init(args->arg1),
						  ipa_init(args->arg2),
						  args->arg3, current(), next);
			return true;
		case SPCI_YIELD_32:
			api_yield(current(), next);

			/* SPCI_YIELD always returns SPCI_SUCCESS. */
			*args = (struct spci_value){.func = SPCI_SUCCESS_32};

			return true;
	    case SPCI_PARTITION_INFO_GET_32:
			*args = api_spci_partition_info_get(current(), args->arg1,
							    args->arg2, args->arg3,
							    args->arg4, eret_origin);
			#if SECURE_WORLD == 1
				if (eret_origin){
			        /* Return to Normal world */
			        smc_res = smc32(args->func, args->arg1,
			                args->arg2, args->arg3,
			                args->arg4, args->arg5,
			                args->arg6, args->arg7);
			        args->func = smc_res.func;
			        args->arg1 = smc_res.arg1;
			        args->arg2 = smc_res.arg2;
			        args->arg3 = smc_res.arg3;
			        args->arg4 = smc_res.arg4;
			        args->arg5 = smc_res.arg5;
			        args->arg6 = smc_res.arg6;
			        args->arg7 = smc_res.arg7;
			        eret_origin = true;
			        break;
				}
	        #endif
			return true;

		case SPCI_MSG_SEND_32:
			*args = api_spci_msg_send(
				spci_msg_send_sender(*args),
				spci_msg_send_receiver(*args),
				spci_msg_send_size(*args),
				spci_msg_send_attributes(*args), current(),
				next);
			return true;
		case SPCI_MSG_WAIT_32:

#if SECURE_WORLD == 1

			spmd_exit(args);
			eret_origin = true;
			break;

#endif

			*args = api_spci_msg_recv(true, current(), next);
			return true;
		case SPCI_MSG_POLL_32:
			*args = api_spci_msg_recv(false, current(), next);
			return true;
		case SPCI_RUN_32:
			*args = api_spci_run(spci_vm_id(*args),
					     spci_vcpu_index(*args), current(),
					     next);
			return true;
		case SPCI_MSG_SEND_DIRECT_REQ_32:

			// dlog("dir req src %#x dest %#X: %#x %#x %#x %#x %#x\n",
			// 	spci_msg_send_sender(*args),spci_msg_send_receiver(*args),
			// 	args->arg3, args->arg4, args->arg5, args->arg6, args->arg7);

			if (is_opposite_world_vm_id(spci_msg_send_receiver(*args)))
			{
				current()->state = VCPU_STATE_BLOCKED_MAILBOX;
				spmd_exit(args);
				eret_origin = true;
				continue;
			}

			*args = api_spci_msg_send_direct_req(args, current(), next);
			return true;
		case SPCI_MSG_SEND_DIRECT_RESP_32:

			// dlog("dir resp src %#x dest %#X: %#x %#x %#x %#x %#x\n",
			// 	spci_msg_send_sender(*args),spci_msg_send_receiver(*args),
			// 	args->arg3, args->arg4, args->arg5, args->arg6, args->arg7);

#if SECURE_WORLD == 1
			/* Check if we're returning from a managed exit. */
			if (current()->cpu->managed_exit){
			         /* Clear the LR that was used to pend the managed exit. */
				switch(current()->cpu->managed_exit){
					case 1:
						write_msr(ICH_LR0_EL2, 0x0);
						break;
					case 2:
						write_msr(ICH_LR1_EL2, 0x0);
						break;
					case 3:
						write_msr(ICH_LR2_EL2, 0x0);
						break;
					case 4:
						write_msr(ICH_LR3_EL2, 0x0);
						break;
					case 5:
						write_msr(ICH_LR4_EL2, 0x0);
						break;
					case 6:
						write_msr(ICH_LR5_EL2, 0x0);
						break;
					case 7:
						write_msr(ICH_LR6_EL2, 0x0);
						break;
					case 8:
						write_msr(ICH_LR7_EL2, 0x0);
						break;
					case 9:
						write_msr(ICH_LR8_EL2, 0x0);
						break;
					case 10:
						write_msr(ICH_LR9_EL2, 0x0);
						break;
					default:
						panic("Unexpected M Exit register: %d\n",
								current()->cpu->managed_exit);
				}

				/* Lower interrupt priority mask. */
				write_msr(ICC_PMR_EL1, 0xFF);

				/* Clear the pending managed exit. */
				current()->cpu->managed_exit = 0;
			}
#endif


			if (is_opposite_world_vm_id(spci_msg_send_receiver(*args)))
			{
				current()->state = VCPU_STATE_BLOCKED_MAILBOX;
				spmd_exit(args);
				eret_origin = true;
				continue;
			}

			*args = api_spci_msg_send_direct_resp(args, current(), next);
			return true;


		case SPCI_MEM_SHARE_64:
		case SPCI_MEM_SHARE_32:

			*args = api_spci_mem_share(
				args->arg1, args->arg2, args->arg3, args->arg4,
				current()->vm, eret_origin);

			if (eret_origin)
			{
				/* SPCI_MEM_SHARE originated on the other world, hence move back. */
				spmd_exit(args);
				break;  // XXX: re-check if needed
			}

			return true;

		case SPCI_MEM_RETRIEVE_REQ_32:
		case SPCI_MEM_RETRIEVE_REQ_64:
			*args = api_spci_mem_retrieve_req(
				args->arg1, args->arg2, args->arg3, args->arg4,
				current()->vm, eret_origin);

			return true;

		case SPCI_MEM_RECLAIM_32:
		case SPCI_MEM_RECLAIM_64:
		{
			uint64_t handle = args->arg2<<32 | args->arg1;
			if (eret_origin)
			{
				api_spci_memory_reclaim(handle, args->arg3, current()->vm);

				/* FWD call back to the other world. */
				spmd_exit(args);
				eret_origin = true;
				break;
			}

			api_spci_memory_reclaim(handle, args->arg3, current()->vm);
			spmd_exit(args);
			eret_origin = true;


			args->func = SPCI_SUCCESS_32;

			return true;

		}
		case SPCI_MEM_RELINQUISH_32:
		case SPCI_MEM_RELINQUISH_64:
			{
				struct mem_relinquish_descriptor *relinquish_desc;

				if (eret_origin)
				{
					#if SECURE_WORLD
						relinquish_desc = (struct mem_relinquish_descriptor *)hv_rx;
					#else
						panic("Relinquish should not be forwared from the secure world.\n");
					#endif
				}
				else
				{
					#if SECURE_WORLD
						relinquish_desc = (struct mem_relinquish_descriptor *)current()->vm->mailbox.send;
					#else
						panic("relinquish is only supported in this proto from S to NS\n");
					#endif
				}
				*args = api_spci_mem_relinquish(relinquish_desc, current()->vm);
				return true;
			}
		case SPCI_MEM_OP_RESUME:
			*args = spci_mem_op_resume_internal(args->arg1, current()->vm);
			return true;

		case SPCI_MEM_FRAG_RX_32:
			*args = spci_mem_frag_rx(args->arg1, args->arg2,
				args->arg3,	args->arg4, current()->vm);
			return true;

		case SPCI_MEM_FRAG_TX_32:
			*args = spci_mem_frag_tx(args->arg1, args->arg2,
				args->arg3,	args->arg4, current()->vm);
			if(eret_origin)
			{
				spmd_exit(args);
				break;
			}

			return true;

		default:
			return false;
		} // switch()
	}  // while(true)

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

bool is_call_allowed(struct vcpu *vcpu, uint32_t func)
{
	if (vcpu->direct_request_origin_vcpu) {
		/*
		 * The vCPU is executing in a SPCI_MSG_SEND_DIRECT_REQ context,
		 * there is a subset of calls that are not allowed to perform.
		 * Strictly speaking any call that does not terminate at the Hv
		 * is blocked. The exception to this is
		 * SPCI_MSG_SEND_DIRECT_RESP which is signals the termination of
		 * a SPCI_MSG_SEND_DIRECT_REQ.
		 */
		switch (func) {
		case SPCI_RUN_32:
		case SPCI_MSG_SEND_32:
		case SPCI_MSG_SEND_DIRECT_REQ_32:
		case SPCI_MSG_POLL_32:
		case SPCI_YIELD_32:
		case SPCI_MSG_WAIT_32:

			dlog("Denied %X smc.\n", func);
			return false;
		default:

			return true;
		}
	}

	return true;
}

/**
 * Processes SMC instruction calls.
 */
static struct vcpu *smc_handler(struct vcpu *vcpu)
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

	if (!is_call_allowed(vcpu, args.func)) {
		/*
		 * Calls are not allowed when a SPCI_MSG_SEND_REQ is being
		 * serviced in the curent vCPU. In general all the calls that
		 * induce a vCPU switch are denied. Only calls defined in the
		 * SPCIv1.0 spec induce a vCPU switch, and all such calls return
		 * a DENIED error code when issued during an ongoing
		 * SPCI_MSG_SEND_REQ.
		 */
		return NULL;
	}

	if (psci_handler(vcpu, args.func, args.arg1, args.arg2, args.arg3,
			 &vcpu->regs.r[0], &next)) {
		return next;
	}

	if (spci_handler(&args, &next)) {
		arch_regs_set_retval(&vcpu->regs, args);
		update_vi(next);
		return next;
	}

	switch (args.func & ~SMCCC_CONVENTION_MASK) {
	case HF_DEBUG_LOG:
		vcpu->regs.r[0] = api_debug_log(args.arg1, vcpu);
		return NULL;
	}

	smc_forwarder(vcpu->vm, &args);
	arch_regs_set_retval(&vcpu->regs, args);
	return NULL;
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
 * Injects an exception with the specified Exception Syndrom Register value into
 * the EL1.
 * See Arm Architecture Reference Manual Armv8-A, page D13-2924.
 *
 * NOTE: This function assumes that the lazy registers haven't been saved, and
 * writes to the lazy registers of the CPU directly instead of the vCPU.
 */
static void inject_el1_exception(struct vcpu *vcpu, uintreg_t esr_el1_value)
{
	uintreg_t handler_address = get_el1_exception_handler_addr(vcpu);

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
}

/**
 * Injects a Data Abort exception (same exception level).
 */
static void inject_el1_data_abort_exception(struct vcpu *vcpu,
					    uintreg_t esr_el2)
{
	/*
	 *  ISS encoding remains the same, but the EC is changed to reflect
	 *  where the exception came from.
	 *  See Arm Architecture Reference Manual Armv8-A, pages D13-2943/2982.
	 */
	uintreg_t esr_el1_value = GET_ESR_ISS(esr_el2) | GET_ESR_IL(esr_el2) |
				  (EC_DATA_ABORT_SAME_EL << ESR_EC_OFFSET);

	dlog_notice("Injecting Data Abort exception into VM%d.\n",
		    vcpu->vm->id);

	inject_el1_exception(vcpu, esr_el1_value);
}

/**
 * Injects a Data Abort exception (same exception level).
 */
static void inject_el1_instruction_abort_exception(struct vcpu *vcpu,
						   uintreg_t esr_el2)
{
	/*
	 *  ISS encoding remains the same, but the EC is changed to reflect
	 *  where the exception came from.
	 *  See Arm Architecture Reference Manual Armv8-A, pages D13-2941/2980.
	 */
	uintreg_t esr_el1_value =
		GET_ESR_ISS(esr_el2) | GET_ESR_IL(esr_el2) |
		(EC_INSTRUCTION_ABORT_SAME_EL << ESR_EC_OFFSET);

	dlog_notice("Injecting Instruction Abort exception into VM%d.\n",
		    vcpu->vm->id);

	inject_el1_exception(vcpu, esr_el1_value);
}

/**
 * Injects an exception with an unknown reason into the EL1.
 */
static void inject_el1_unknown_exception(struct vcpu *vcpu, uintreg_t esr_el2)
{
	uintreg_t esr_el1_value =
		GET_ESR_IL(esr_el2) | (EC_UNKNOWN << ESR_EC_OFFSET);
	char *direction_str;

	direction_str = ISS_IS_READ(esr_el2) ? "read" : "write";
	dlog_notice(
		"Trapped access to system register %s: op0=%d, op1=%d, crn=%d, "
		"crm=%d, op2=%d, rt=%d.\n",
		direction_str, GET_ISS_OP0(esr_el2), GET_ISS_OP1(esr_el2),
		GET_ISS_CRN(esr_el2), GET_ISS_CRM(esr_el2),
		GET_ISS_OP2(esr_el2), GET_ISS_RT(esr_el2));

	dlog_notice("Injecting Unknown Reason exception into VM%d.\n",
		    vcpu->vm->id);

	inject_el1_exception(vcpu, esr_el1_value);
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

	if (!is_call_allowed(vcpu, args.func)) {
		/*
		 * Calls are not allowed when a SPCI_MSG_SEND_REQ is being
		 * serviced in the curent vCPU. In general all the calls that
		 * induce a vCPU switch are denied. Only calls defined in the
		 * SPCIv1.0 spec induce a vCPU switch, and all such calls return
		 * a DENIED error code when issued during an ongoing
		 * SPCI_MSG_SEND_REQ.
		 */
		vcpu->regs.r[0] = SPCI_ERROR_32;
		vcpu->regs.r[2] = SPCI_DENIED;
		return next;
	}

	if (psci_handler(vcpu, args.func, args.arg1, args.arg2, args.arg3,
			 &vcpu->regs.r[0], &next)) {
		return next;
	}

	if (spci_handler(&args, &next)) {
		arch_regs_set_retval(&vcpu->regs, args);
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
	/* Program the list register. */
	uint64_t value =  (uint64_t) 1 << 62	// Pending
			| (uint64_t) 0 << 60 	// Group 0
			| (uint64_t) 0x8 << 48	// Priority
			| (uint64_t) 0xA << 0	// intid
		;

	/* Find and Empty List register to use. */
	if (read_msr(ICH_LR0_EL2) == 0) {
		write_msr(ICH_LR0_EL2, value);
		current()->cpu->managed_exit = 1;
	}
	else if (read_msr(ICH_LR1_EL2) == 0) {
		write_msr(ICH_LR1_EL2, value);
		current()->cpu->managed_exit = 2;
	}
	else if (read_msr(ICH_LR2_EL2) == 0) {
		write_msr(ICH_LR2_EL2, value);
		current()->cpu->managed_exit = 3;
	}
	else if (read_msr(ICH_LR3_EL2) == 0) {
		write_msr(ICH_LR3_EL2, value);
		current()->cpu->managed_exit = 4;
	}
	else if (read_msr(ICH_LR4_EL2) == 0) {
		write_msr(ICH_LR4_EL2, value);
		current()->cpu->managed_exit = 5;
	}
	else if (read_msr(ICH_LR5_EL2) == 0) {
		write_msr(ICH_LR5_EL2, value);
		current()->cpu->managed_exit = 6;
	}
	else if (read_msr(ICH_LR6_EL2) == 0) {
		write_msr(ICH_LR6_EL2, value);
		current()->cpu->managed_exit = 7;
	}
	else if (read_msr(ICH_LR7_EL2) == 0) {
		write_msr(ICH_LR7_EL2, value);
		current()->cpu->managed_exit = 8;
	}
	else if (read_msr(ICH_LR8_EL2) == 0) {
		write_msr(ICH_LR8_EL2, value);
		current()->cpu->managed_exit = 9;
	}
	else if (read_msr(ICH_LR9_EL2) == 0) {
		write_msr(ICH_LR9_EL2, value);
		current()->cpu->managed_exit = 10;
	}
	else {
		panic("No Free List Registers\n");
	}

	/* Raise minimum priority to prevent interrupt re triggering
	 into SPM and allow servicing of SGI */
	write_msr(ICC_PMR_EL1, 0x10);

	return current();
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
	case EC_WFI_WFE:
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

	case EC_DATA_ABORT_LOWER_EL:
		info = fault_info_init(
			esr, vcpu, (esr & (1U << 6)) ? MM_MODE_W : MM_MODE_R);
		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}
		/* Inform the EL1 of the data abort. */
		inject_el1_data_abort_exception(vcpu, esr);

		/* Schedule the same VM to continue running. */
		return NULL;

	case EC_INSTRUCTION_ABORT_LOWER_EL:
		info = fault_info_init(esr, vcpu, MM_MODE_X);
		if (vcpu_handle_page_fault(vcpu, &info)) {
			return NULL;
		}
		/* Inform the EL1 of the instruction abort. */
		inject_el1_instruction_abort_exception(vcpu, esr);

		/* Schedule the same VM to continue running. */
		return NULL;

	case EC_HVC:
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
			"Unknown lower sync exception pc=%#x, esr=%#x, "
			"ec=%#x\n",
			vcpu->regs.pc, esr, ec);
		break;
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
	spci_vm_id_t vm_id = vcpu->vm->id;
	uintreg_t ec = GET_ESR_EC(esr_el2);

	CHECK(ec == EC_MSR);
	/*
	 * Handle accesses to debug and performance monitor registers.
	 * Inject an exception for unhandled/unsupported registers.
	 */
	if (debug_el1_is_register_access(esr_el2)) {
		if (!debug_el1_process_access(vcpu, vm_id, esr_el2)) {
			inject_el1_unknown_exception(vcpu, esr_el2);
			return;
		}
	} else if (perfmon_is_register_access(esr_el2)) {
		if (!perfmon_process_access(vcpu, vm_id, esr_el2)) {
			inject_el1_unknown_exception(vcpu, esr_el2);
			return;
		}
	} else if (feature_id_is_register_access(esr_el2)) {
		if (!feature_id_process_access(vcpu, esr_el2)) {
			inject_el1_unknown_exception(vcpu, esr_el2);
			return;
		}
	} else {
		inject_el1_unknown_exception(vcpu, esr_el2);
		return;
	}

	/* Instruction was fulfilled. Skip it and run the next one. */
	vcpu->regs.pc += GET_NEXT_PC_INC(esr_el2);
}
