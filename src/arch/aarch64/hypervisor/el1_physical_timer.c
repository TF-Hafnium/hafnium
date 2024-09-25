/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "el1_physical_timer.h"

#include "hf/dlog.h"

#include "msr.h"
#include "sysregs.h"

/* clang-format off */

/**
 * EL1 Physical Timer register encodings as defined in section D19.12 of the
 * ARMv8 ARM (DDI0487 J.a).
 * TYPE, op0, op1, crn, crm, op2
 */
#define CNTP_REGISTERS          \
	X(CTL, 3, 3, 14, 2, 1)  \
	X(CVAL, 3, 3, 14, 2, 2) \
	X(TVAL, 3, 3, 14, 2, 0)

#if SECURE_WORLD == 1
#define HOST_TIMER_REG(type) MSR_CNTHPS_##type##_EL2
#else
#define HOST_TIMER_REG(type) MSR_CNTHP_##type##_EL2
#endif

/* clang-format on */

/**
 * Returns true if the ESR register shows an access to a EL1 Physical Timer
 * register.
 */
bool el1_physical_timer_is_register_access(uintreg_t esr)
{
	uintreg_t sys_register = GET_ISS_SYSREG(esr);
	bool is_timer_access;

	switch (sys_register) {
#define X(type, op0, op1, crn, crm, op2)                  \
	case (GET_ISS_ENCODING(op0, op1, crn, crm, op2)): \
		is_timer_access = true;                   \
		break;
		CNTP_REGISTERS
#undef X
	default:
		is_timer_access = false;
	}

	return is_timer_access;
}

/**
 * Access to CNTP timer register is trapped and emulated using S-EL2
 * physical timer.
 */
bool el1_physical_timer_process_access(struct vcpu *vcpu, uintreg_t esr)
{
	uintreg_t sys_register = GET_ISS_SYSREG(esr);
	uintreg_t rt_register = GET_ISS_RT(esr);
	uintreg_t value;

	if (ISS_IS_READ(esr)) {
		switch (sys_register) {
#define X(type, op0, op1, crn, crm, op2)                  \
	case (GET_ISS_ENCODING(op0, op1, crn, crm, op2)): \
		value = read_msr(HOST_TIMER_REG(type));   \
		vcpu->regs.r[rt_register] = value;        \
		break;
			CNTP_REGISTERS
#undef X
		default:
			dlog_notice(
				"Unsupported timer register read: op0=%lu, "
				"op1=%lu, crn=%lu, crm=%lu, op2=%lu, rt=%lu.\n",
				GET_ISS_OP0(esr), GET_ISS_OP1(esr),
				GET_ISS_CRN(esr), GET_ISS_CRM(esr),
				GET_ISS_OP2(esr), GET_ISS_RT(esr));
			break;
		}
	} else {
		value = vcpu->regs.r[rt_register];
		switch (sys_register) {
#define X(type, op0, op1, crn, crm, op2)                  \
	case (GET_ISS_ENCODING(op0, op1, crn, crm, op2)): \
		write_msr(HOST_TIMER_REG(type), value);   \
		break;
			CNTP_REGISTERS
#undef X
		default:
			dlog_notice(
				"Unsupported timer register write: op0=%lu, "
				"op1=%lu, crn=%lu, crm=%lu, op2=%lu, rt=%lu, "
				"value=%lu.\n",
				GET_ISS_OP0(esr), GET_ISS_OP1(esr),
				GET_ISS_CRN(esr), GET_ISS_CRM(esr),
				GET_ISS_OP2(esr), GET_ISS_RT(esr), value);
			break;
		}
	}

	return true;
}
