/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/sve.h"

#include "hf/types.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

#include "sysregs.h"

/**
 * Other world SIMD SVE context.
 * By design the VM struct stores FPU/Adv. SIMD contexts but no SIMD context
 * for newer extensions. The structure below supplements the VM struct with
 * SVE context just for the other world VM usage.
 * Restricting to the other world VM limits the required memory footprint when
 * compared to a design where the VM struct holds the full FPU/Adv. SIMD/SVE
 * contexts. There is no immediate requirement to extend the VM struct provided
 * SVE is not enabled for secure partitions (or secondary VMs).
 */
static struct {
	/** SMCCCv1.3 FID[16] hint bit state recorded on SPMC entry from NWd. */
	bool hint;
	uint64_t zcr_el2;
	struct sve_context sve_context;
} ns_simd_ctx[MAX_CPUS];

/**
 * Restore FPU/Adv. SIMD/SVE 'Other world' context when exiting the SPMC.
 * Called from exceptions.S: other_world_loop.
 */
void plat_restore_ns_simd_context(struct vcpu *vcpu)
{
	uint32_t cpu_id;

	assert(vcpu->vm->id == HF_HYPERVISOR_VM_ID);
	cpu_id = cpu_index(vcpu->cpu);

	if (is_arch_feat_sve_supported()) {
		/* Disable SVE EL2 and lower traps. */
		arch_sve_disable_traps();

		/* Configure EL2 vector length to maximum permitted value. */
		arch_sve_configure_vector_length();
	}

	/* Restore FPCR/FPSR common to FPU/Adv. SIMD/SVE. */
	__asm__ volatile(
		"msr fpsr, %0;"
		"msr fpcr, %1"
		:
		: "r"(vcpu->regs.fpsr), "r"(vcpu->regs.fpcr));

	if (is_arch_feat_sve_supported() && !ns_simd_ctx[cpu_id].hint) {
		/* Restore FFR register before predicates. */
		__asm__ volatile(
			".arch_extension sve;"
			"ldr p0, [%0];"
			"wrffr p0.b;"
			".arch_extension nosve"
			:
			: "r"(&ns_simd_ctx[cpu_id].sve_context.ffr));

		/* Restore predicate registers. */
		__asm__ volatile(
			".arch_extension sve;"
			"ldr p0, [%0, #0, MUL VL];"
			"ldr p1, [%0, #1, MUL VL];"
			"ldr p2, [%0, #2, MUL VL];"
			"ldr p3, [%0, #3, MUL VL];"
			"ldr p4, [%0, #4, MUL VL];"
			"ldr p5, [%0, #5, MUL VL];"
			"ldr p6, [%0, #6, MUL VL];"
			"ldr p7, [%0, #7, MUL VL];"
			"ldr p8, [%0, #8, MUL VL];"
			"ldr p9, [%0, #9, MUL VL];"
			"ldr p10, [%0, #10, MUL VL];"
			"ldr p11, [%0, #11, MUL VL];"
			"ldr p12, [%0, #12, MUL VL];"
			"ldr p13, [%0, #13, MUL VL];"
			"ldr p14, [%0, #14, MUL VL];"
			"ldr p15, [%0, #15, MUL VL];"
			".arch_extension nosve"
			:
			: "r"(&ns_simd_ctx[cpu_id].sve_context.predicates));

		/* Restore SVE vectors. */
		__asm__ volatile(
			".arch_extension sve;"
			"ldr z0, [%0, #0, MUL VL];"
			"ldr z1, [%0, #1, MUL VL];"
			"ldr z2, [%0, #2, MUL VL];"
			"ldr z3, [%0, #3, MUL VL];"
			"ldr z4, [%0, #4, MUL VL];"
			"ldr z5, [%0, #5, MUL VL];"
			"ldr z6, [%0, #6, MUL VL];"
			"ldr z7, [%0, #7, MUL VL];"
			"ldr z8, [%0, #8, MUL VL];"
			"ldr z9, [%0, #9, MUL VL];"
			"ldr z10, [%0, #10, MUL VL];"
			"ldr z11, [%0, #11, MUL VL];"
			"ldr z12, [%0, #12, MUL VL];"
			"ldr z13, [%0, #13, MUL VL];"
			"ldr z14, [%0, #14, MUL VL];"
			"ldr z15, [%0, #15, MUL VL];"
			"ldr z16, [%0, #16, MUL VL];"
			"ldr z17, [%0, #17, MUL VL];"
			"ldr z18, [%0, #18, MUL VL];"
			"ldr z19, [%0, #19, MUL VL];"
			"ldr z20, [%0, #20, MUL VL];"
			"ldr z21, [%0, #21, MUL VL];"
			"ldr z22, [%0, #22, MUL VL];"
			"ldr z23, [%0, #23, MUL VL];"
			"ldr z24, [%0, #24, MUL VL];"
			"ldr z25, [%0, #25, MUL VL];"
			"ldr z26, [%0, #26, MUL VL];"
			"ldr z27, [%0, #27, MUL VL];"
			"ldr z28, [%0, #28, MUL VL];"
			"ldr z29, [%0, #29, MUL VL];"
			"ldr z30, [%0, #30, MUL VL];"
			"ldr z31, [%0, #31, MUL VL];"
			".arch_extension nosve"
			:
			: "r"(&ns_simd_ctx[cpu_id].sve_context.vectors));
	} else {
		/* Restore FPU/Adv. SIMD vectors. */
		__asm__ volatile(
			"ldp q0, q1, [%0], #32;"
			"ldp q2, q3, [%0], #32;"
			"ldp q4, q5, [%0], #32;"
			"ldp q6, q7, [%0], #32;"
			"ldp q8, q9, [%0], #32;"
			"ldp q10, q11, [%0], #32;"
			"ldp q12, q13, [%0], #32;"
			"ldp q14, q15, [%0], #32;"
			"ldp q16, q17, [%0], #32;"
			"ldp q18, q19, [%0], #32;"
			"ldp q20, q21, [%0], #32;"
			"ldp q22, q23, [%0], #32;"
			"ldp q24, q25, [%0], #32;"
			"ldp q26, q27, [%0], #32;"
			"ldp q28, q29, [%0], #32;"
			"ldp q30, q31, [%0], #32"
			:
			: "r"(&vcpu->regs.fp));
	}

	if (is_arch_feat_sve_supported()) {
		/*
		 * Restore normal world ZCR_EL2.
		 * ZCR_EL1 is untouched as SVE is not enabled for SPs.
		 */
		write_msr(MSR_ZCR_EL2, ns_simd_ctx[cpu_id].zcr_el2);
		isb();

		/* TODO: enable EL2 and lower traps. */
	}
}

/**
 * Save FPU/Adv SIMD/SVE 'Other world' context when entering the SPMC.
 * Called from handler.c: smc_handler_from_nwd.
 */
void plat_save_ns_simd_context(struct vcpu *vcpu)
{
	uint32_t cpu_id;
	uint64_t smc_fid;

	assert(vcpu->vm->id == HF_HYPERVISOR_VM_ID);
	cpu_id = cpu_index(vcpu->cpu);

	/* Get SMCCCv1.3 SMC FID[16] SVE hint, and clear it from vCPU r0. */
	smc_fid = vcpu->regs.r[0];
	ns_simd_ctx[cpu_id].hint = ((smc_fid >> 16) & 1) != 0;
	vcpu->regs.r[0] &= ~(1 << 16);

	if (is_arch_feat_sve_supported()) {
		/* Disable SVE EL2 and lower traps. */
		arch_sve_disable_traps();

		/*
		 * Save current ZCR_EL2 value, in particular to preserve
		 * NS context SVE Vector Length.
		 */
		ns_simd_ctx[cpu_id].zcr_el2 = read_msr(MSR_ZCR_EL2);

		/* Configure EL2 SVE Vector Length. */
		arch_sve_configure_vector_length();
	}

	/* Save FPCR/FPSR common to FPU/Adv. SIMD/SVE. */
	__asm__ volatile(
		"mrs %0, fpsr;"
		"mrs %1, fpcr"
		: "=r"(vcpu->regs.fpsr), "=r"(vcpu->regs.fpcr));

	if (is_arch_feat_sve_supported() && !ns_simd_ctx[cpu_id].hint) {
		/*
		 * NOTE: When SSVE is disabled, the SVE Vector length applies.
		 * When SSVE is enabled, the SSVL applies.
		 */

		/* Save SVE predicate registers. */
		__asm__ volatile(
			".arch_extension sve;"
			"str p0, [%0, #0, MUL VL];"
			"str p1, [%0, #1, MUL VL];"
			"str p2, [%0, #2, MUL VL];"
			"str p3, [%0, #3, MUL VL];"
			"str p4, [%0, #4, MUL VL];"
			"str p5, [%0, #5, MUL VL];"
			"str p6, [%0, #6, MUL VL];"
			"str p7, [%0, #7, MUL VL];"
			"str p8, [%0, #8, MUL VL];"
			"str p9, [%0, #9, MUL VL];"
			"str p10, [%0, #10, MUL VL];"
			"str p11, [%0, #11, MUL VL];"
			"str p12, [%0, #12, MUL VL];"
			"str p13, [%0, #13, MUL VL];"
			"str p14, [%0, #14, MUL VL];"
			"str p15, [%0, #15, MUL VL];"
			".arch_extension nosve"
			:
			: "r"(&ns_simd_ctx[cpu_id].sve_context.predicates));

		/* Save SVE FFR register. */
		__asm__ volatile(
			".arch_extension sve;"
			"rdffr p0.b;"
			"str p0, [%0];"
			".arch_extension nosve"
			:
			: "r"(&ns_simd_ctx[cpu_id].sve_context.ffr));

		/* Save SVE vector registers. */
		__asm__ volatile(
			".arch_extension sve;"
			"str z0, [%0, #0, MUL VL];"
			"str z1, [%0, #1, MUL VL];"
			"str z2, [%0, #2, MUL VL];"
			"str z3, [%0, #3, MUL VL];"
			"str z4, [%0, #4, MUL VL];"
			"str z5, [%0, #5, MUL VL];"
			"str z6, [%0, #6, MUL VL];"
			"str z7, [%0, #7, MUL VL];"
			"str z8, [%0, #8, MUL VL];"
			"str z9, [%0, #9, MUL VL];"
			"str z10, [%0, #10, MUL VL];"
			"str z11, [%0, #11, MUL VL];"
			"str z12, [%0, #12, MUL VL];"
			"str z13, [%0, #13, MUL VL];"
			"str z14, [%0, #14, MUL VL];"
			"str z15, [%0, #15, MUL VL];"
			"str z16, [%0, #16, MUL VL];"
			"str z17, [%0, #17, MUL VL];"
			"str z18, [%0, #18, MUL VL];"
			"str z19, [%0, #19, MUL VL];"
			"str z20, [%0, #20, MUL VL];"
			"str z21, [%0, #21, MUL VL];"
			"str z22, [%0, #22, MUL VL];"
			"str z23, [%0, #23, MUL VL];"
			"str z24, [%0, #24, MUL VL];"
			"str z25, [%0, #25, MUL VL];"
			"str z26, [%0, #26, MUL VL];"
			"str z27, [%0, #27, MUL VL];"
			"str z28, [%0, #28, MUL VL];"
			"str z29, [%0, #29, MUL VL];"
			"str z30, [%0, #30, MUL VL];"
			"str z31, [%0, #31, MUL VL];"
			".arch_extension nosve"
			:
			: "r"(&ns_simd_ctx[cpu_id].sve_context.vectors));
	} else {
		/* Save FPU/Adv. SIMD vectors. */
		__asm__ volatile(
			"stp q0, q1, [%0], #32;"
			"stp q2, q3, [%0], #32;"
			"stp q4, q5, [%0], #32;"
			"stp q6, q7, [%0], #32;"
			"stp q8, q9, [%0], #32;"
			"stp q10, q11, [%0], #32;"
			"stp q12, q13, [%0], #32;"
			"stp q14, q15, [%0], #32;"
			"stp q16, q17, [%0], #32;"
			"stp q18, q19, [%0], #32;"
			"stp q20, q21, [%0], #32;"
			"stp q22, q23, [%0], #32;"
			"stp q24, q25, [%0], #32;"
			"stp q26, q27, [%0], #32;"
			"stp q28, q29, [%0], #32;"
			"stp q30, q31, [%0], #32"
			:
			: "r"(&vcpu->regs.fp));
	}
}
