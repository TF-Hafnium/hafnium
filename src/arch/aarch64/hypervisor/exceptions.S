/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/offsets.h"

#include "hf/arch/vmid_base.h"

#include "msr.h"
#include "exception_macros.S"
#include "sysregs_defs.h"

/**
 * Saves the volatile registers into the register buffer of the current vCPU.
 */
.macro save_volatile_to_vcpu
	/*
	 * Save x18 since we're about to clobber it. We subtract 16 instead of
	 * 8 from the stack pointer to keep it 16-byte aligned.
	 */
	str x18, [sp, #-16]!

	/* Get the current vCPU. */
	mrs x18, tpidr_el2
	stp x0, x1, [x18, #VCPU_REGS + 8 * 0]
	stp x2, x3, [x18, #VCPU_REGS + 8 * 2]
	stp x4, x5, [x18, #VCPU_REGS + 8 * 4]
	stp x6, x7, [x18, #VCPU_REGS + 8 * 6]
	stp x8, x9, [x18, #VCPU_REGS + 8 * 8]
	stp x10, x11, [x18, #VCPU_REGS + 8 * 10]
	stp x12, x13, [x18, #VCPU_REGS + 8 * 12]
	stp x14, x15, [x18, #VCPU_REGS + 8 * 14]
	stp x16, x17, [x18, #VCPU_REGS + 8 * 16]
	stp x29, x30, [x18, #VCPU_REGS + 8 * 29]

	/* x18 was saved on the stack, so we move it to vCPU regs buffer. */
	ldr x0, [sp], #16
	str x0, [x18, #VCPU_REGS + 8 * 18]

	/* Save return address & mode. */
	mrs x1, elr_el2
	mrs x2, spsr_el2
	stp x1, x2, [x18, #VCPU_REGS + 8 * 31]
.endm

/**
 * This is a generic handler for exceptions taken at a lower EL. It saves the
 * volatile registers to the current vCPU and calls the C handler, which can
 * select one of two paths: (a) restore volatile registers and return, or
 * (b) switch to a different vCPU. In the latter case, the handler needs to save
 * all non-volatile registers (they haven't been saved yet), then restore all
 * registers from the new vCPU.
 */
.macro lower_exception handler:req
	save_volatile_to_vcpu

	bl enable_vhe_tge

#if BRANCH_PROTECTION
	/* NOTE: x18 still holds pointer to current vCPU. */
	bl pauth_save_vcpu_and_restore_hyp_key
#endif

#if ENABLE_MTE
	bl mte_save_vcpu_and_restore_hyp_state
#endif

	/* Call C handler. */
	bl \handler

	/* Switch vCPU if requested by handler. */
	cbnz x0, vcpu_switch

	/* vCPU is not changing. */
	mrs x0, tpidr_el2
	b vcpu_restore_volatile_and_run
.endm

/**
 * This is the handler for a sync exception taken at a lower EL.
 */
.macro lower_sync_exception
	save_volatile_to_vcpu

	bl enable_vhe_tge

#if BRANCH_PROTECTION
	/* NOTE: x18 still holds pointer to current vCPU. */
	bl pauth_save_vcpu_and_restore_hyp_key
#endif

#if ENABLE_MTE
	bl mte_save_vcpu_and_restore_hyp_state
#endif

	/* Extract the exception class (EC) from exception syndrome register. */
	mrs x18, esr_el2
	lsr x18, x18, #26

	/* Take the system register path for EC 0x18. */
	sub x18, x18, #0x18
	cbz x18, system_register_access

	/* Call C handler passing the syndrome and fault address registers. */
	mrs x0, esr_el2
	mrs x1, far_el2
	bl sync_lower_exception

	/* Switch vCPU if requested by handler. */
	cbnz x0, vcpu_switch

	/* vCPU is not changing. */
	mrs x0, tpidr_el2
	b vcpu_restore_volatile_and_run
.endm

/**
 * The following is the exception table. A pointer to it will be stored in
 * register vbar_el2.
 */
.section .text.vector_table_el2, "ax"
.global vector_table_el2
.balign 0x800
vector_table_el2:
sync_cur_sp0:
	noreturn_current_exception_sp0 el2 sync_current_exception_noreturn

.balign 0x80
irq_cur_sp0:
	noreturn_current_exception_sp0 el2 irq_current_exception_noreturn

.balign 0x80
fiq_cur_sp0:
	noreturn_current_exception_sp0 el2 fiq_current_exception_noreturn

.balign 0x80
serr_cur_sp0:
	noreturn_current_exception_sp0 el2 serr_current_exception_noreturn

.balign 0x80
sync_cur_spx:
	noreturn_current_exception_spx el2 sync_current_exception_noreturn

.balign 0x80
irq_cur_spx:
	noreturn_current_exception_spx el2 irq_current_exception_noreturn

.balign 0x80
fiq_cur_spx:
	noreturn_current_exception_spx el2 fiq_current_exception_noreturn

.balign 0x80
serr_cur_spx:
	noreturn_current_exception_spx el2 serr_current_exception_noreturn

.balign 0x80
sync_lower_64:
	lower_sync_exception

.balign 0x80
irq_lower_64:
	lower_exception irq_lower

.balign 0x80
fiq_lower_64:
	lower_exception fiq_lower

.balign 0x80
serr_lower_64:
	lower_exception serr_lower

.balign 0x80
sync_lower_32:
	lower_sync_exception

.balign 0x80
irq_lower_32:
	lower_exception irq_lower

.balign 0x80
fiq_lower_32:
	lower_exception fiq_lower

.balign 0x80
serr_lower_32:
	lower_exception serr_lower

.balign 0x40

/**
 * pauth_save_vcpu_and_restore_hyp_key
 *
 * NOTE: expect x18 holds pointer to current vCPU.
 */
#if BRANCH_PROTECTION
pauth_save_vcpu_and_restore_hyp_key:
	/*
	 * Save APIA key for the vCPU as Hypervisor replaces it with its
	 * own key. Other vCPU PAuth keys are taken care in vcpu_switch.
	 */
	add	x0, x18, #VCPU_PAC
	mrs     x1, APIAKEYLO_EL1
	mrs     x2, APIAKEYHI_EL1
	stp	x1, x2, [x0]

	/* Restore Hypervisor APIA key. */
	pauth_restore_hypervisor_key x0 x1
	ret
#endif

/**
 * mte_save_vcpu_and_restore_hyp_state
 */
#if ENABLE_MTE
mte_save_vcpu_and_restore_hyp_state:
	add	x0, x18, #VCPU_MTE
	mrs	x1, tfsr_el1
	mrs	x2, gcr_el1
	mrs	x3, rgsr_el1
	mrs	x4, tfsre0_el1
	stp	x1, x2, [x0], #16
	stp	x3, x4, [x0]

	mte_restore_hypervisor_state x0

	ret
#endif

/**
 * Handle accesses to system registers (EC=0x18) and return to original caller.
 */
system_register_access:
	/*
	 * Non-volatile registers are (conservatively) saved because the handler
	 * can clobber non-volatile registers that are used by the msr/mrs,
	 * which results in the wrong value being read or written.
	 */
	/* Get the current vCPU. */
	mrs x18, tpidr_el2
	stp x19, x20, [x18, #VCPU_REGS + 8 * 19]
	stp x21, x22, [x18, #VCPU_REGS + 8 * 21]
	stp x23, x24, [x18, #VCPU_REGS + 8 * 23]
	stp x25, x26, [x18, #VCPU_REGS + 8 * 25]
	stp x27, x28, [x18, #VCPU_REGS + 8 * 27]

	/* Read syndrome register and call C handler. */
	mrs x0, esr_el2
	bl handle_system_register_access

	/* Continue running the same vCPU. */
	mrs x0, tpidr_el2
	b vcpu_restore_nonvolatile_and_run

/**
 * Switch to a new vCPU.
 *
 * All volatile registers from the old vCPU have already been saved. We need
 * to save only non-volatile ones from the old vCPU, and restore all from the
 * new one.
 *
 * x0 is a pointer to the new vCPU.
 */
vcpu_switch:
	/* Save non-volatile registers. */
	mrs x1, tpidr_el2
	stp x19, x20, [x1, #VCPU_REGS + 8 * 19]
	stp x21, x22, [x1, #VCPU_REGS + 8 * 21]
	stp x23, x24, [x1, #VCPU_REGS + 8 * 23]
	stp x25, x26, [x1, #VCPU_REGS + 8 * 25]
	stp x27, x28, [x1, #VCPU_REGS + 8 * 27]

	/* Save lazy state. */
	/* Use x28 as the base */
	add x28, x1, #VCPU_LAZY

	/* Check if VHE support is enabled, equivalent to has_vhe_support(). */
	mrs x19, id_aa64mmfr1_el1
	tst x19, #(ID_AA64MMFR1_EL1_VH_MASK << ID_AA64MMFR1_EL1_VH_SHIFT)
	b.ne vhe_save

	mrs x24, sctlr_el1
	mrs x25, cpacr_el1
	stp x24, x25, [x28], #16

	mrs x2, ttbr0_el1
	mrs x3, ttbr1_el1
	stp x2, x3, [x28], #16

	mrs x4, tcr_el1
	mrs x5, esr_el1
	stp x4, x5, [x28], #16

	mrs x6, afsr0_el1
	mrs x7, afsr1_el1
	stp x6, x7, [x28], #16

	mrs x8, far_el1
	mrs x9, mair_el1
	stp x8, x9, [x28], #16

	mrs x10, vbar_el1
	mrs x11, contextidr_el1
	stp x10, x11, [x28], #16

	mrs x12, amair_el1
	mrs x13, cntkctl_el1
	stp x12, x13, [x28], #16

	mrs x14, elr_el1
	mrs x15, spsr_el1
	stp x14, x15, [x28], #16

	b skip_vhe_save

vhe_save:
	mrs x24, MSR_SCTLR_EL12
	mrs x25, MSR_CPACR_EL12
	stp x24, x25, [x28], #16

	mrs x2, MSR_TTBR0_EL12
	mrs x3, MSR_TTBR1_EL12
	stp x2, x3, [x28], #16

	mrs x4, MSR_TCR_EL12
	mrs x5, MSR_ESR_EL12
	stp x4, x5, [x28], #16

	mrs x6, MSR_AFSR0_EL12
	mrs x7, MSR_AFSR1_EL12
	stp x6, x7, [x28], #16

	mrs x8, MSR_FAR_EL12
	mrs x9, MSR_MAIR_EL12
	stp x8, x9, [x28], #16

	mrs x10, MSR_VBAR_EL12
	mrs x11, MSR_CONTEXTIDR_EL12
	stp x10, x11, [x28], #16

	mrs x12, MSR_AMAIR_EL12
	mrs x13, MSR_CNTKCTL_EL12
	stp x12, x13, [x28], #16

	mrs x14, MSR_ELR_EL12
	mrs x15, MSR_SPSR_EL12
	stp x14, x15, [x28], #16

skip_vhe_save:
	mrs x16, vmpidr_el2
	mrs x17, csselr_el1
	stp x16, x17, [x28], #16

	mrs x18, actlr_el1
	mrs x19, tpidr_el0
	stp x18, x19, [x28], #16

	mrs x20, tpidrro_el0
	mrs x21, tpidr_el1
	stp x20, x21, [x28], #16

	mrs x22, sp_el0
	mrs x23, sp_el1
	stp x22, x23, [x28], #16

	mrs x24, vtcr_el2
	mrs x25, vttbr_el2
	stp x24, x25, [x28], #16

#if SECURE_WORLD == 1
	mrs x26, MSR_VSTCR_EL2
	mrs x27, MSR_VSTTBR_EL2
	stp x26, x27, [x28], #16
#else
	stp xzr, xzr, [x28], #16
#endif

	mrs x4, mdcr_el2
	mrs x5, mdscr_el1
	stp x4, x5, [x28], #16

	mrs x6, pmccfiltr_el0
	mrs x7, pmcr_el0
	stp x6, x7, [x28], #16

	mrs x8, pmcntenset_el0
	mrs x9, pmintenset_el1
	stp x8, x9, [x28], #16

	mrs x10, cnthctl_el2
	mrs x11, par_el1
	stp x10, x11, [x28], #16

#if BRANCH_PROTECTION
	add x2, x1, #(VCPU_PAC + 16)
	mrs x10, APIBKEYLO_EL1
	mrs x11, APIBKEYHI_EL1
	stp x10, x11, [x2], #16
	mrs x12, APDAKEYLO_EL1
	mrs x13, APDAKEYHI_EL1
	stp x12, x13, [x2], #16
	mrs x14, APDBKEYLO_EL1
	mrs x15, APDBKEYHI_EL1
	stp x14, x15, [x2], #16
	mrs x16, APGAKEYLO_EL1
	mrs x17, APGAKEYHI_EL1
	stp x16, x17, [x2], #16
#endif

	/* Save GIC registers. */
#if GIC_VERSION == 3 || GIC_VERSION == 4
	/* Offset is too large, so start from a new base. */
	add x2, x1, #VCPU_GIC

	mrs x3, ich_hcr_el2
	mrs x4, icc_sre_el2
	stp x3, x4, [x2, #16 * 0]
#endif

	/* Save floating point registers. */
	/* Use x28 as the base. */
	add x28, x1, #VCPU_FREGS
	simd_op_vectors stp, x28
	mrs x3, fpsr
	mrs x4, fpcr
	stp x3, x4, [x28]

	/* Save new vCPU pointer in non-volatile register. */
	mov x19, x0

	/*
	 * Save peripheral registers, and inform the arch-independent sections
	 * that registers have been saved.
	 */
	mov x0, x1
	bl complete_saving_state
	mov x0, x19

	/* Intentional fallthrough. */

/**
 * vcpu_restore_all_and_run
 *
 * Called from hypervisor entry after cpu_main has returned in 'x0' the address
 * of a vCPU to be resumed on current PE. Either way, fall through from above,
 * in case of a vCPU switch happens with or without world change.
 * Additionally, for the SPMC case cpu_main can return a vCPU from the 'other
 * world VM' in which case this queries returning to the normal world.
 */
.global vcpu_restore_all_and_run
vcpu_restore_all_and_run:

#if SECURE_WORLD == 1

	/* Check if vCPU to switch to is from 'other world' VM. */
	ldr x1, [x0, #VCPU_VM]
	ldrh w1, [x1, #VM_ID]

	/* Exit to normal world if VM id is HF_OTHER_WORLD_ID. */
	cmp w1, #HF_OTHER_WORLD_ID
	bne 0f

	/*
	 * The current vCPU state is saved, or SPMC exits after a cold or
	 * warm boot. It's now safe to switch to the normal world.
	 */

	/* Update pointer to current vCPU. */
	msr tpidr_el2, x0

	mov x19, x0
other_world_loop:
	/* Restore FP status and control registers. */
	add x18, x19, #VCPU_FPSR
	ldp x0, x1, [x18]
	msr fpsr, x0
	msr fpcr, x1

	/* Check if SVE is implemented. */
	bl is_arch_feat_sve_supported
	cbnz x0, sve_context_restore

	/* Restore the other world SIMD context to the other world VM vCPU. */
	add x18, x19, #VCPU_FREGS
	simd_op_vectors ldp, x18
	b sve_skip_context_restore

	/* Restore the other world SVE context from internal buffer. */
sve_context_restore:
	adrp x18, sve_context
	add x18, x18, :lo12: sve_context
	ldr x0, [x19, #VCPU_CPU]
	bl cpu_index
	mov x20, #SVE_CTX_SIZE
	madd x18, x0, x20, x18

.arch_extension sve
	/* Restore FFR register before predicates. */
	ldr p0, [x18]
	wrffr p0.b

	/* Restore predicate registers. */
	add x20, x18, #SVE_CTX_PREDICATES
	sve_predicate_op ldr, x20

	/* Restore vector registers. */
	add x20, x18, #SVE_CTX_VECTORS
	sve_op_vectors ldr, x20
.arch_extension nosve

sve_skip_context_restore:
	/*
	 * Prepare arguments from other world VM vCPU.
	 * x19 holds the other world VM vCPU pointer.
	 */
	ldp x0, x1, [x19, #VCPU_REGS + 8 * 0]
	ldp x2, x3, [x19, #VCPU_REGS + 8 * 2]
	ldp x4, x5, [x19, #VCPU_REGS + 8 * 4]
	ldp x6, x7, [x19, #VCPU_REGS + 8 * 6]
	ldp x8, x9, [x19, #VCPU_REGS + 8 * 8]
	ldp x10, x11, [x19, #VCPU_REGS + 8 * 10]
	ldp x12, x13, [x19, #VCPU_REGS + 8 * 12]
	ldp x14, x15, [x19, #VCPU_REGS + 8 * 14]
	ldp x16, x17, [x19, #VCPU_REGS + 8 * 16]

#if BRANCH_PROTECTION
	/*
	 * EL3 saves pointer authentication keys when entering by SMC.
	 * Although prefer clearing the keys to be on the safe side.
	 */
	msr APIAKEYLO_EL1, xzr
	msr APIAKEYHI_EL1, xzr
	msr APIBKEYLO_EL1, xzr
	msr APIBKEYHI_EL1, xzr
	msr APDAKEYLO_EL1, xzr
	msr APDAKEYHI_EL1, xzr
	msr APDBKEYLO_EL1, xzr
	msr APDBKEYHI_EL1, xzr
	msr APGAKEYLO_EL1, xzr
	msr APGAKEYHI_EL1, xzr
	/* Omit ISB as SMC following is a context synchronizing event. */
#endif

#if ENABLE_MTE
	/* Clearing MTE context. */
	msr rgsr_el1, xzr
	msr tfsr_el1, xzr
	msr tfsr_el2, xzr
	msr tfsre0_el1, xzr
#endif

	smc #0

	/*
	 * The call to EL3 returned, First eight GP registers contain an FF-A
	 * call from the physical FF-A instance. Save those arguments to the
	 * other world VM vCPU.
	 * x19 is restored with the other world VM vCPU pointer.
	 */
	stp x0, x1, [x19, #VCPU_REGS + 8 * 0]
	stp x2, x3, [x19, #VCPU_REGS + 8 * 2]
	stp x4, x5, [x19, #VCPU_REGS + 8 * 4]
	stp x6, x7, [x19, #VCPU_REGS + 8 * 6]
	stp x8, x9, [x19, #VCPU_REGS + 8 * 8]
	stp x10, x11, [x19, #VCPU_REGS + 8 * 10]
	stp x12, x13, [x19, #VCPU_REGS + 8 * 12]
	stp x14, x15, [x19, #VCPU_REGS + 8 * 14]
	stp x16, x17, [x19, #VCPU_REGS + 8 * 16]

	/* Save FP status and control registers. */
	mrs x0, fpsr
	mrs x1, fpcr
	add x18, x19, #VCPU_FPSR
	stp x0, x1, [x18]

	/* Check if SVE is implemented. */
	bl is_arch_feat_sve_supported
	cbnz x0, sve_context_save

	/* Save the other world SIMD context to the other world VM vCPU. */
	add x18, x19, #VCPU_FREGS
	simd_op_vectors stp, x18
	b sve_skip_context_save

	/* Save the other world SVE context to internal buffer. */
sve_context_save:
	adrp x18, sve_context
	add x18, x18, :lo12: sve_context
	ldr x0, [x19, #VCPU_CPU]
	bl cpu_index
	mov x20, #SVE_CTX_SIZE
	madd x18, x0, x20, x18

.arch_extension sve
	/* Save predicate registers. */
	add x20, x18, #SVE_CTX_PREDICATES
	sve_predicate_op str, x20

	/* Save FFR register after predicates. */
	rdffr p0.b
	str p0, [x18]

	/* Save vector registers. */
	add x20, x18, #SVE_CTX_VECTORS
	sve_op_vectors str, x20
.arch_extension nosve

sve_skip_context_save:

#if BRANCH_PROTECTION
	pauth_restore_hypervisor_key x0 x1
#endif

#if ENABLE_MTE
	mte_restore_hypervisor_state x0
#endif

	/*
	 * Stack is at top and execution can restart straight into C code.
	 * Handle the FF-A call from other world.
	 */
	mov x0, x19
	bl smc_handler_from_nwd

	/*
	 * If the smc handler returns null this indicates no vCPU has to be
	 * resumed and GP registers contain a fresh FF-A response or call
	 * directed to the normal world. Hence loop back and emit SMC again.
	 * Otherwise restore the vCPU pointed to by the handler return value.
	 */
	cbz x0, other_world_loop
#endif /* SECURE_WORLD */

	/* Intentional fallthrough. */

	/* Update pointer to current vCPU. */
0:	msr tpidr_el2, x0

	/* Restore peripheral registers. */
	mov x19, x0
	bl begin_restoring_state
	mov x0, x19

	/*
	 * Restore floating point registers.
	 */
	add x2, x0, #VCPU_FREGS
	simd_op_vectors ldp, x2
	ldp x3, x4, [x2]
	msr fpsr, x3

	/*
	 * Only restore FPCR if changed, to avoid expensive
	 * self-synchronising operation where possible.
	 */
	mrs x5, fpcr
	cmp x5, x4
	b.eq vcpu_restore_lazy_and_run
	msr fpcr, x4
	/* Intentional fallthrough. */

vcpu_restore_lazy_and_run:
	/* Restore lazy registers. */
	/* Use x28 as the base. */
	add x28, x0, #VCPU_LAZY

	/* Check if VHE support is enabled, equivalent to has_vhe_support(). */
	mrs x19, id_aa64mmfr1_el1
	tst x19, #(ID_AA64MMFR1_EL1_VH_MASK << ID_AA64MMFR1_EL1_VH_SHIFT)
	b.ne vhe_restore

	ldp x24, x25, [x28], #16
	msr sctlr_el1, x24
	msr cpacr_el1, x25

	ldp x2, x3, [x28], #16
	msr ttbr0_el1, x2
	msr ttbr1_el1, x3

	ldp x4, x5, [x28], #16
	msr tcr_el1, x4
	msr esr_el1, x5

	ldp x6, x7, [x28], #16
	msr afsr0_el1, x6
	msr afsr1_el1, x7

	ldp x8, x9, [x28], #16
	msr far_el1, x8
	msr mair_el1, x9

	ldp x10, x11, [x28], #16
	msr vbar_el1, x10
	msr contextidr_el1, x11

	ldp x12, x13, [x28], #16
	msr amair_el1, x12
	msr cntkctl_el1, x13

	ldp x14, x15, [x28], #16
	msr elr_el1, x14
	msr spsr_el1, x15
	b skip_vhe_restore

vhe_restore:
	ldp x24, x25, [x28], #16
	msr MSR_SCTLR_EL12, x24
	msr MSR_CPACR_EL12, x25

	ldp x2, x3, [x28], #16
	msr MSR_TTBR0_EL12, x2
	msr MSR_TTBR1_EL12, x3

	ldp x4, x5, [x28], #16
	msr MSR_TCR_EL12, x4
	msr MSR_ESR_EL12, x5

	ldp x6, x7, [x28], #16
	msr MSR_AFSR0_EL12, x6
	msr MSR_AFSR1_EL12, x7

	ldp x8, x9, [x28], #16
	msr MSR_FAR_EL12, x8
	msr MSR_MAIR_EL12, x9

	ldp x10, x11, [x28], #16
	msr MSR_VBAR_EL12, x10
	msr MSR_CONTEXTIDR_EL12, x11

	ldp x12, x13, [x28], #16
	msr MSR_AMAIR_EL12, x12
	msr MSR_CNTKCTL_EL12, x13

	ldp x14, x15, [x28], #16
	msr MSR_ELR_EL12, x14
	msr MSR_SPSR_EL12, x15

skip_vhe_restore:
	ldp x16, x17, [x28], #16
	msr vmpidr_el2, x16
	msr csselr_el1, x17

	ldp x18, x19, [x28], #16
	msr actlr_el1, x18
	msr tpidr_el0, x19

	ldp x20, x21, [x28], #16
	msr tpidrro_el0, x20
	msr tpidr_el1, x21

	ldp x22, x23, [x28], #16
	msr sp_el0, x22
	msr sp_el1, x23

	ldp x24, x25, [x28], #16
	msr vtcr_el2, x24
	msr vttbr_el2, x25

	ldp x26, x27, [x28], #16
#if SECURE_WORLD == 1
	msr MSR_VSTCR_EL2, x26
	msr MSR_VSTTBR_EL2, x27
#endif

	ldp x4, x5, [x28], #16
	msr mdcr_el2, x4
	msr mdscr_el1, x5

	ldp x6, x7, [x28], #16
	msr pmccfiltr_el0, x6
	msr pmcr_el0, x7

	ldp x8, x9, [x28], #16
	/*
	 * NOTE: Writing 0s to pmcntenset_el0's bits do not alter their values.
	 * To reset them, clear the register by writing to pmcntenclr_el0.
	 */
	mov x27, #0xffffffff
	msr pmcntenclr_el0, x27
	msr pmcntenset_el0, x8

	/*
	 * NOTE: Writing 0s to pmintenset_el1's bits do not alter their values.
	 * To reset them, clear the register by writing to pmintenclr_el1.
	 */
	msr pmintenclr_el1, x27
	msr pmintenset_el1, x9

	ldp x10, x11, [x28], #16
	msr cnthctl_el2, x10
	msr par_el1, x11

#if BRANCH_PROTECTION
	add x2, x0, #(VCPU_PAC + 16)
	ldp x10, x11, [x2], #16
	msr APIBKEYLO_EL1, x10
	msr APIBKEYHI_EL1, x11
	ldp x12, x13, [x2], #16
	msr APDAKEYLO_EL1, x12
	msr APDAKEYHI_EL1, x13
	ldp x14, x15, [x2], #16
	msr APDBKEYLO_EL1, x14
	msr APDBKEYHI_EL1, x15
	ldp x16, x17, [x2], #16
	msr APGAKEYLO_EL1, x16
	msr APGAKEYHI_EL1, x17
#endif

	/* Restore GIC registers. */
#if GIC_VERSION == 3 || GIC_VERSION == 4
	/* Offset is too large, so start from a new base. */
	add x2, x0, #VCPU_GIC

	ldp x3, x4, [x2, #16 * 0]
	msr ich_hcr_el2, x3
	msr icc_sre_el2, x4
#endif

	/*
	 * If a different vCPU is being run on this physical CPU to the last one
	 * which was run for this VM, invalidate the TLB. This must be called
	 * after vttbr_el2 has been updated, so that we have the page table and
	 * VMID of the vCPU to which we are switching.
	 */
	mov x19, x0
	bl maybe_invalidate_tlb
	mov x0, x19

	/* Intentional fallthrough. */

vcpu_restore_nonvolatile_and_run:
	/* Restore non-volatile registers. */
	ldp x19, x20, [x0, #VCPU_REGS + 8 * 19]
	ldp x21, x22, [x0, #VCPU_REGS + 8 * 21]
	ldp x23, x24, [x0, #VCPU_REGS + 8 * 23]
	ldp x25, x26, [x0, #VCPU_REGS + 8 * 25]
	ldp x27, x28, [x0, #VCPU_REGS + 8 * 27]

	/* Intentional fallthrough. */
/**
 * Restore volatile registers and run the given vCPU.
 *
 * x0 is a pointer to the target vCPU.
 */
vcpu_restore_volatile_and_run:
#if BRANCH_PROTECTION
	add	x1, x0, #VCPU_PAC
	ldp	x1, x2, [x1]

	/* Restore vCPU APIA key. */
	msr     APIAKEYLO_EL1, x1
	msr     APIAKEYHI_EL1, x2
	/* Omit ISB as ERET following is a context synchronizing event. */
#endif

#if ENABLE_MTE
	/* Restore vCPU MTE state. */
	add	x1, x0, #VCPU_MTE
	ldp	x2, x3, [x1], #16
	msr	tfsr_el1, x2
	msr	gcr_el1, x3
	ldp	x2, x3, [x1]
	msr	rgsr_el1, x2
	msr	tfsre0_el1, x3
	/* Omit ISB as ERET following is a context synchronizing event. */
#endif

	ldp x4, x5, [x0, #VCPU_REGS + 8 * 4]
	ldp x6, x7, [x0, #VCPU_REGS + 8 * 6]
	ldp x8, x9, [x0, #VCPU_REGS + 8 * 8]
	ldp x10, x11, [x0, #VCPU_REGS + 8 * 10]
	ldp x12, x13, [x0, #VCPU_REGS + 8 * 12]
	ldp x14, x15, [x0, #VCPU_REGS + 8 * 14]
	ldp x16, x17, [x0, #VCPU_REGS + 8 * 16]
	ldr x18, [x0, #VCPU_REGS + 8 * 18]
	ldp x29, x30, [x0, #VCPU_REGS + 8 * 29]

	/* Restore return address & mode. */
	ldp x1, x2, [x0, #VCPU_REGS + 8 * 31]
	msr elr_el2, x1
	msr spsr_el2, x2

	ldp x1, x2, [x0, #VCPU_REGS + 8 * 33]
	ldp x3, xzr, [x0, #VCPU_REGS + 8 * 35]
	msr hcr_el2, x1
	isb

	msr ttbr0_el2, x2
	msr sctlr_el2, x3
	isb

	/* Restore x0..x3, which we have used as scratch before. */
	ldp x2, x3, [x0, #VCPU_REGS + 8 * 2]
	ldp x0, x1, [x0, #VCPU_REGS + 8 * 0]
	eret_with_sb

enable_vhe_tge:
	mrs x0, id_aa64mmfr1_el1
	tst x0, #(ID_AA64MMFR1_EL1_VH_MASK << ID_AA64MMFR1_EL1_VH_SHIFT)
	b.eq 1f

	/**
	 * Apply Hypervisor/SPMC configuration when VHE is enabled:
	 * Switch to host mode (HCR_EL2.{E2H, TGE} = {1,1}).
	 * Note that E2H is always set when VHE is enabled.
	 * Enable alignment check (SCTLR_EL2.A).
	 * Switch TTBR0_EL2 to host page tables (ASID 0 tables).
	 */
	adrp x0, arch_mm_config
	add x0, x0, :lo12:arch_mm_config
	ldp x3, xzr, [x0]
	ldp x1, x2, [x0, #0x18]
	msr hcr_el2, x2
	isb

	msr sctlr_el2, x1
	msr ttbr0_el2, x3
	isb

1:	ret
