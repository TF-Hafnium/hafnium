/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/types.h"

#include "hf/vcpu.h"

void arch_fpu_state_save_to_vcpu(struct vcpu *vcpu)
{
	__asm__ volatile(
		".arch_extension fp;"
		"mrs %0, fpsr;"
		"mrs %1, fpcr;"
		".arch_extension nofp;"
		: "=r"(vcpu->regs.fpsr), "=r"(vcpu->regs.fpcr));
}

void arch_fpu_regs_save_to_vcpu(struct vcpu *vcpu)
{
	__asm__ volatile(
		".arch_extension fp;"
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
		"stp q30, q31, [%0], #32;"
		".arch_extension nofp;"
		:
		: "r"(&vcpu->regs.fp));
}

void arch_fpu_save_to_vcpu(struct vcpu *vcpu)
{
	arch_fpu_state_save_to_vcpu(vcpu);
	arch_fpu_regs_save_to_vcpu(vcpu);
}

void arch_fpu_state_restore_from_vcpu(struct vcpu *vcpu)
{
	__asm__ volatile(
		".arch_extension fp;"
		"msr fpsr, %0;"
		"msr fpcr, %1;"
		".arch_extension nofp;"
		:
		: "r"(vcpu->regs.fpsr), "r"(vcpu->regs.fpcr));
}

void arch_fpu_regs_restore_from_vcpu(struct vcpu *vcpu)
{
	__asm__ volatile(
		".arch_extension fp;"
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
		"ldp q30, q31, [%0], #32;"
		".arch_extension nofp;"
		:
		: "r"(&vcpu->regs.fp));
}

void arch_fpu_restore_from_vcpu(struct vcpu *vcpu)
{
	arch_fpu_state_restore_from_vcpu(vcpu);
	arch_fpu_regs_restore_from_vcpu(vcpu);
}
