/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/timer.h"

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "ffa_endpoints.h"
#include "gicv3.h"
#include "msr.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define TEST_SP_PREEMPTED_BY_NS_INTERRUPT_LOOP_COUNT UINT64_C(1000000)

SET_UP(interrupts)
{
	gicv3_system_setup();
}

TEAR_DOWN(interrupts)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
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
	struct ffa_partition_info receiver;

	EXPECT_EQ(get_ffa_partition_info(
			  &(struct ffa_uuid){SP_SERVICE_FIRST_UUID}, &receiver,
			  1),
		  1);

	interrupt_enable(PHYSICAL_TIMER_IRQ, true);
	interrupt_set_priority(PHYSICAL_TIMER_IRQ, 0x80);
	interrupt_set_edge_triggered(PHYSICAL_TIMER_IRQ, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();

	/*
	 * Check that no (SGI or PPI) interrupts are active or pending to start
	 * with.
	 */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);

	HFTEST_LOG("Starting timer\n");
	/* Set physical timer for 20 ms and enable. */
	write_msr(CNTP_TVAL_EL0, ns_to_ticks(20000000));
	write_msr(CNTP_CTL_EL0, CNTx_CTL_ENABLE_MASK);

	/* Send direct request to query SP to wait in a busy loop. */
	struct ffa_value res = sp_busy_loop_cmd_send(
		hf_vm_get_id(), receiver.vm_id,
		TEST_SP_PREEMPTED_BY_NS_INTERRUPT_LOOP_COUNT);

	/* SP is pre-empted by the non-secure timer interrupt. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/* VM id/vCPU index are passed through arg1. */
	EXPECT_EQ(res.arg1, ffa_vm_vcpu(receiver.vm_id, 0));

	/* Waiting for interrupt to be serviced in normal world. */
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Check that we got the interrupt. */
	HFTEST_LOG("Checking for interrupt\n");
	EXPECT_EQ(last_interrupt_id, PHYSICAL_TIMER_IRQ);
	/* Check timer status. */
	EXPECT_EQ(read_msr(CNTP_CTL_EL0),
		  CNTx_CTL_ISTS_MASK | CNTx_CTL_ENABLE_MASK);

	/* There should again be no pending or active interrupts. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);

	/* Resume the SP to complete the busy loop and return with success. */
	res = ffa_run(ffa_vm_id(res), ffa_vcpu_index(res));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);
}
