/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/types.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/timer.h"

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "ffa_endpoints.h"
#include "ffa_secure_partitions.h"
#include "gicv3.h"
#include "msr.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"
#include "wdog.h"

#define TEST_SP_PREEMPTED_BY_NS_INTERRUPT_LOOP_COUNT UINT64_C(1000000)

SET_UP(interrupts)
{
	gicv3_system_setup();
}

TEAR_DOWN(interrupts)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

void setup_wdog_timer_interrupt(void)
{
	interrupt_enable(IRQ_WDOG_INTID, true);
	interrupt_set_priority(IRQ_WDOG_INTID, 0x80);
	interrupt_set_edge_triggered(IRQ_WDOG_INTID, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();
}

void start_wdog_timer(uint32_t time_ms)
{
	HFTEST_LOG("Starting wdog timer\n");
	wdog_start((time_ms * ARM_SP805_WDOG_CLK_HZ) / 1000);
}

static void check_wdog_timer_interrupt_serviced(void)
{
	/* Waiting for interrupt to be serviced in normal world. */
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Check that we got the interrupt. */
	HFTEST_LOG("Checking for interrupt\n");
	EXPECT_EQ(last_interrupt_id, IRQ_WDOG_INTID);

	/* Stop the watchdog timer. */
	wdog_stop();

	/* There should again be no pending or active interrupts. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
}

/**
 * This test arms a timer in the normal world and emits a direct request to a
 * secure partition to query for a busy loop. The timer physical PPI NS
 * interrupt traps to Hafnium/SPMC which saves the currently running SP vCPU
 * state and returns to the normal world. The latter traps to the irq handler
 * and handles the timer interrupt. The SP vCPU is then resumed again through
 * FFA_RUN which completes the busy loop and returns a sucess direct msg
 * response.
 */
TEST(interrupts, sp_preempted_by_ns_interrupt)
{
	struct ffa_value res;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *receiver_info = service2(mb.recv);
	const ffa_id_t receiver_id = receiver_info->vm_id;

	setup_wdog_timer_interrupt();
	start_wdog_timer(20);

	/* Send direct request to query SP to wait in a busy loop. */
	res = sp_busy_loop_cmd_send(
		hf_vm_get_id(), receiver_id,
		TEST_SP_PREEMPTED_BY_NS_INTERRUPT_LOOP_COUNT);

	/* SP is pre-empted by the non-secure timer interrupt. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/* VM id/vCPU index are passed through arg1. */
	EXPECT_EQ(res.arg1, ffa_vm_vcpu(receiver_id, 0));

	check_wdog_timer_interrupt_serviced();

	/* Resume the SP to complete the busy loop and return with success. */
	res = ffa_run(ffa_vm_id(res), ffa_vcpu_index(res));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);
}

/**
 * This test arms a timer in the normal world and emits a direct request to a
 * secure partition to query for a busy loop. The timer physical PPI NS
 * interrupt traps to Hafnium/SPMC at S-EL2 as FIQ. SPMC injects a managed
 * exit vIRQ interrupt(as requested by the secure partition through the
 * `managed-exit-virq` field in its manifest). Further, SPMC resumes the SP
 * causing it to run its interrupt handler. SP sends a managed exit (direct
 * message) response to the normal world. The latter traps to the irq handler
 * and handles the timer interrupt. The SP vCPU is then resumed again through
 * a special direct message request which completes the busy loop and returns
 * a success direct msg response.
 */
TEST(interrupts, sp_managed_exit)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *receiver_info = service1(mb.recv);
	const ffa_id_t receiver_id = receiver_info->vm_id;

	setup_wdog_timer_interrupt();

	/* Enable SP to handle managed exit. */
	res = sp_virtual_interrupt_cmd_send(own_id, receiver_id,
					    HF_MANAGED_EXIT_INTID, true,
					    INTERRUPT_TYPE_IRQ);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	start_wdog_timer(20);
	/* Send direct request to query SP to wait in a busy loop. */
	res = sp_busy_loop_cmd_send(
		hf_vm_get_id(), receiver_id,
		TEST_SP_PREEMPTED_BY_NS_INTERRUPT_LOOP_COUNT);

	/* Expect a managed exit response from SP. */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), HF_MANAGED_EXIT_INTID);

	check_wdog_timer_interrupt_serviced();

	/* Resume the SP to complete the busy loop and return with success. */
	res = sp_resume_after_managed_exit_send(own_id, receiver_id);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);
}
