/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "gicv3.h"
#include "msr.h"
#include "test/hftest.h"

/**
 * Converts a number of nanoseconds to the equivalent number of timer ticks.
 */
static uint64_t ns_to_ticks(uint64_t ns)
{
	return ns * read_msr(cntfrq_el0) / NANOS_PER_UNIT;
}

SET_UP(busy_secondary)
{
	system_setup();
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	SERVICE_SELECT(SERVICE_VM1, "busy", send_buffer);
}

TEST(busy_secondary, virtual_timer)
{
	const char message[] = "loop";
	struct ffa_value run_res;

	interrupt_enable(VIRTUAL_TIMER_IRQ, true);
	interrupt_set_priority(VIRTUAL_TIMER_IRQ, 0x80);
	interrupt_set_edge_triggered(VIRTUAL_TIMER_IRQ, true);
	/*
	 * Hypervisor timer IRQ is needed for Hafnium to return control to the
	 * primary if the (emulated) virtual timer fires while the secondary is
	 * running.
	 */
	interrupt_enable(HYPERVISOR_TIMER_IRQ, true);
	interrupt_set_priority(HYPERVISOR_TIMER_IRQ, 0x80);
	interrupt_set_edge_triggered(HYPERVISOR_TIMER_IRQ, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();

	/* Let the secondary get started and wait for our message. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/* Check that no interrupts are active or pending to start with. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);

	/* Let secondary start looping. */
	dlog("Telling secondary to loop.\n");
	memcpy_s(send_buffer, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_EQ(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		FFA_SUCCESS_32);

	dlog("Starting timer\n");
	/* Set virtual timer for 3 mS and enable. */
	write_msr(CNTV_TVAL_EL0, ns_to_ticks(3000000));
	write_msr(CNTV_CTL_EL0, 0x00000001);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_INTERRUPT_32);

	dlog("Waiting for interrupt\n");
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Check that we got the interrupt. */
	dlog("Checking for interrupt\n");
	EXPECT_EQ(last_interrupt_id, VIRTUAL_TIMER_IRQ);
	/* Check timer status. */
	EXPECT_EQ(read_msr(CNTV_CTL_EL0), 0x00000005);

	/* There should again be no pending or active interrupts. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
}

TEST(busy_secondary, physical_timer)
{
	const char message[] = "loop";
	struct ffa_value run_res;

	interrupt_enable(PHYSICAL_TIMER_IRQ, true);
	interrupt_set_priority(PHYSICAL_TIMER_IRQ, 0x80);
	interrupt_set_edge_triggered(PHYSICAL_TIMER_IRQ, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();

	/* Let the secondary get started and wait for our message. */
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);
	EXPECT_EQ(run_res.arg2, FFA_SLEEP_INDEFINITE);

	/* Check that no interrupts are active or pending to start with. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);

	/* Let secondary start looping. */
	dlog("Telling secondary to loop.\n");
	memcpy_s(send_buffer, FFA_MSG_PAYLOAD_MAX, message, sizeof(message));
	EXPECT_EQ(
		ffa_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, sizeof(message), 0)
			.func,
		FFA_SUCCESS_32);

	dlog("Starting timer\n");
	/* Set physical timer for 3 ms and enable. */
	write_msr(CNTP_TVAL_EL0, ns_to_ticks(3000000));
	write_msr(CNTP_CTL_EL0, 0x00000001);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_INTERRUPT_32);

	dlog("Waiting for interrupt\n");
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Check that we got the interrupt. */
	dlog("Checking for interrupt\n");
	EXPECT_EQ(last_interrupt_id, PHYSICAL_TIMER_IRQ);
	/* Check timer status. */
	EXPECT_EQ(read_msr(CNTP_CTL_EL0), 0x00000005);

	/* There should again be no pending or active interrupts. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
}
