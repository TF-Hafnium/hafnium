/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hf/arch/types.h"

#include "hf/addr.h"
#include "hf/vcpu.h"

#include "vmapi/hf/ffa.h"

/**
 * Reset the register values other than the PC and argument which are set with
 * `arch_regs_set_pc_arg()`.
 */
void arch_regs_reset(struct vcpu *vcpu);

/**
 * Updates the given registers so that when a vCPU runs, it starts off at the
 * given address (pc) with the given argument.
 *
 * This function must only be called on an arch_regs that is known not be in use
 * by any other physical CPU.
 */
void arch_regs_set_pc_arg(struct arch_regs *r, ipaddr_t pc, uintreg_t arg);

/**
 * Verifies the `gp_reg_num` complies with the number of registers available in
 * the architecture.
 */
bool arch_regs_reg_num_valid(uint32_t gp_reg_num);

/**
 * Sets the value of a general purpose register.
 */
void arch_regs_set_gp_reg(struct arch_regs *r, uintreg_t value,
			  uint32_t gp_reg_num);

/**
 * Updates the register holding the return value of a function.
 *
 * This function must only be called on an arch_regs that is known not be in use
 * by any other physical CPU.
 */
void arch_regs_set_retval(struct arch_regs *r, struct ffa_value v);

/**
 * Extracts SMC or HVC arguments from the registers of a vCPU.
 *
 * This function must only be called on an arch_regs that is known not be in use
 * by any other physical CPU.
 */
struct ffa_value arch_regs_get_args(struct arch_regs *regs);

/**
 * Initialize and reset CPU-wide register values.
 */
void arch_cpu_init(struct cpu *c);

struct vcpu *arch_vcpu_resume(struct cpu *c);

uint32_t arch_affinity_to_core_pos(uint64_t reg);

uint32_t arch_find_core_pos(void);
