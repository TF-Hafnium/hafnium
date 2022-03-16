/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/cpu.h"

#include "hf/cpu.h"
#include "hf/ffa.h"
#include "hf/plat/interrupts.h"

void arch_irq_disable(void)
{
	/* TODO */
}

void arch_irq_enable(void)
{
	/* TODO */
}

void arch_regs_reset(struct vcpu *vcpu)
{
	/* TODO */
	(void)vcpu;
}

void arch_regs_set_pc_arg(struct arch_regs *r, ipaddr_t pc, uintreg_t arg)
{
	(void)pc;
	r->arg[0] = arg;
}

bool arch_regs_reg_num_valid(const unsigned int gp_reg_num)
{
	(void)gp_reg_num;
	return false;
}

void arch_regs_set_gp_reg(struct arch_regs *r, uintreg_t value,
			  const unsigned int gp_reg_num)
{
	(void)r;
	(void)value;
	(void)gp_reg_num;
}

void arch_regs_set_retval(struct arch_regs *r, struct ffa_value v)
{
	r->arg[0] = v.func;
	r->arg[1] = v.arg1;
	r->arg[2] = v.arg2;
	r->arg[3] = v.arg3;
	r->arg[4] = v.arg4;
	r->arg[5] = v.arg5;
	r->arg[6] = v.arg6;
	r->arg[7] = v.arg7;
}

void arch_cpu_init(struct cpu *c)
{
	plat_interrupts_controller_hw_init(c);
}
