/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "test/vmapi/arch/exception_handler.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "sysregs.h"
#include "test/hftest.h"

/**
 * Arm ARM states bit 31 of MPIDR register must be RES1. This mask can be used
 * to clear it while extracting vCPU index from read of MPIDR_EL1 register.
 */
#define MPIDR_RES1_CLEAR_MASK (~(UINT64_C(1) << 31))

/**
 * Tracks the number of times the exception handler has been invoked.
 */
static int exception_handler_exception_count = 0;

/**
 * Tracks the virtual interrupt that was last handled by indexed execution
 * context of an SP.
 */
static uint32_t last_serviced_interrupt[MAX_CPUS] = {HF_INVALID_INTID};

/**
 * Used to specify an instruction address to return to after exception
 * is handled.
 */
static uint64_t exception_handler_return_addr = 0;

/**
 * Get the index of the current vCPU.
 */
ffa_vcpu_index_t get_current_vcpu_index(void)
{
	ffa_vcpu_index_t index;

	index = read_msr(mpidr_el1) & MPIDR_RES1_CLEAR_MASK;
	EXPECT_LT(index, MAX_CPUS);

	return index;
}

/**
 * Sends the number of exceptions handled to the Primary VM.
 */
void exception_handler_send_exception_count(void)
{
	struct ffa_partition_msg *exception_msg =
		(struct ffa_partition_msg *)SERVICE_SEND_BUFFER();

	dlog("Sending exception_count %d to primary VM\n",
	     exception_handler_exception_count);

	/*
	 * TODO: remove use of HF_PRIMARY_VM_ID, replace with a mechanism that
	 * allows to detect the caller to a running test service. This may
	 * eventually become to be another endpoint, different from primary VM.
	 */
	ffa_rxtx_header_init(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(int),
			     &exception_msg->header);
	memcpy_s(exception_msg->payload, FFA_MSG_PAYLOAD_MAX,
		 (const void *)&exception_handler_exception_count,
		 sizeof(exception_handler_exception_count));
	EXPECT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
	ffa_yield();
}

/**
 * Receives the number of exceptions handled.
 */
int exception_handler_receive_exception_count(const void *recv_buf)
{
	struct ffa_partition_msg *exception_msg =
		(struct ffa_partition_msg *)recv_buf;
	int exception_count = *((const int *)exception_msg->payload);
	struct ffa_value ret;
	ffa_notifications_bitmap_t fwk_notif;

	ret = ffa_notification_get(hf_vm_get_id(), 0,
				   FFA_NOTIFICATION_FLAG_BITMAP_HYP |
					   FFA_NOTIFICATION_FLAG_BITMAP_SPM);

	fwk_notif = ffa_notification_get_from_framework(ret);

	if (fwk_notif == 0U ||
	    exception_msg->header.size != sizeof(exception_count)) {
		return 0;
	}

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	return exception_count;
}

/**
 * EL1 exception handler to use in unit test VMs.
 * Skips the instruction that triggered the exception.
 */
bool exception_handler_skip_instruction(void)
{
	dlog("%s function is triggered!\n", __func__);
	++exception_handler_exception_count;

	/* Skip instruction that triggered the exception. */
	uint64_t next_pc = read_msr(elr_el1);
	next_pc += 4UL;
	write_msr(elr_el1, next_pc);

	/* Indicate that elr_el1 should not be restored. */
	return true;
}

/**
 * Warning: Intended to be used only in test code.
 * The ability to jump to any address after an exception could
 * possibily be exploited by malicious code.
 *
 * Sets the specified instruction address to return to after handler exits.
 */
void exception_handler_set_return_addr(uint64_t instr_addr)
{
	exception_handler_return_addr = instr_addr;
}

/**
 * Returns the specified instruction address to return to after handler exits.
 */
static uint64_t exception_handler_get_return_addr(void)
{
	return exception_handler_return_addr;
}

/**
 * EL1 exception handler to use in unit test VMs.
 * Skips to the instruction address specified in general
 * register x19.
 */
bool exception_handler_skip_to_instruction(void)
{
	dlog("%s function is triggered!\n", __func__);
	++exception_handler_exception_count;

	uint64_t instr_addr = exception_handler_get_return_addr();

	if (instr_addr) {
		write_msr(elr_el1, instr_addr);
		/* Indicate that elr_el1 should not be restored. */
		return true;
	}

	dlog_error("%s: Return address not set, restoring elr_el1\n", __func__);
	return false;
}

/**
 * EL1 exception handler to use in unit test VMs.
 * Yields control back to the hypervisor and sends the number of exceptions.
 */
static bool exception_handler_yield(void)
{
	dlog("%s function is triggered!\n", __func__);
	++exception_handler_exception_count;

	exception_handler_send_exception_count();

	/* Indicate that elr_el1 should not be restored. */
	return true;
}

/**
 * EL1 exception handler to use in unit test VMs.
 * Yields control back to the hypervisor and sends the number of exceptions.
 * Asserts that the Exception Class is Unknown.
 */
bool exception_handler_yield_unknown(void)
{
	uintreg_t esr_el1 = read_msr(ESR_EL1);
	uintreg_t far_el1 = read_msr(FAR_EL1);

	EXPECT_EQ(GET_ESR_EC(esr_el1), EC_UNKNOWN);

	/*
	 * For unknown exceptions, the value of far_el1 is UNKNOWN.
	 * Hafnium sets it to 0.
	 */
	EXPECT_EQ(far_el1, 0);

	return exception_handler_yield();
}

/**
 * EL1 exception handler to use in unit test VMs.
 * Yields control back to the hypervisor and sends the number of exceptions.
 * Asserts that the Exception Class is Data Abort (same EL).
 */
bool exception_handler_yield_data_abort(void)
{
	uintreg_t esr_el1 = read_msr(ESR_EL1);
	uintreg_t far_el1 = read_msr(FAR_EL1);

	EXPECT_EQ(GET_ESR_EC(esr_el1), EC_DATA_ABORT_SAME_EL);
	EXPECT_NE(far_el1, 0);

	return exception_handler_yield();
}

/**
 * EL1 exception handler to use in unit test VMs.
 * Yields control back to the hypervisor and sends the number of exceptions.
 * Asserts that the Exception Class is Instruction Abort (same EL).
 */
bool exception_handler_yield_instruction_abort(void)
{
	uintreg_t esr_el1 = read_msr(ESR_EL1);
	uintreg_t far_el1 = read_msr(FAR_EL1);

	EXPECT_EQ(GET_ESR_EC(esr_el1), EC_INSTRUCTION_ABORT_SAME_EL);
	EXPECT_NE(far_el1, 0);

	return exception_handler_yield();
}

/**
 * Returns the number of times the instruction handler was invoked.
 */
int exception_handler_get_num(void)
{
	return exception_handler_exception_count;
}

/**
 * Resets the number of exceptions counter;
 */
void exception_handler_reset(void)
{
	exception_handler_exception_count = 0;
}

/**
 * Updates the last serviced virtual interrupt ID for the given vCPU.
 */
void exception_handler_set_last_interrupt(uint32_t int_id)
{
	last_serviced_interrupt[get_current_vcpu_index()] = int_id;
}

/**
 * Returns the last serviced virtual interrupt ID for the given vCPU.
 */
uint32_t exception_handler_get_last_interrupt(void)
{
	return last_serviced_interrupt[get_current_vcpu_index()];
}
