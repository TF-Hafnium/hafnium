/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/delay.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/timer.h"

#include "ffa_secure_partitions.h"
#include "gicv3.h"
#include "partition_services.h"
#include "sp_helpers.h"

#define SP_SLEEP_TIME 400U
#define NS_SLEEP_TIME 200U

static void configure_trusted_wdog_interrupt(ffa_vm_id_t source,
					     ffa_vm_id_t dest, bool enable)
{
	struct ffa_value res;

	res = sp_virtual_interrupt_cmd_send(source, dest, IRQ_TWDOG_INTID,
					    enable, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void enable_trusted_wdog_interrupt(ffa_vm_id_t source, ffa_vm_id_t dest)
{
	configure_trusted_wdog_interrupt(source, dest, true);
}

static void disable_trusted_wdog_interrupt(ffa_vm_id_t source, ffa_vm_id_t dest)
{
	configure_trusted_wdog_interrupt(source, dest, false);
}

static void enable_trigger_trusted_wdog_timer(ffa_vm_id_t own_id,
					      ffa_vm_id_t receiver_id,
					      uint32_t timer_ms)
{
	struct ffa_value res;

	/* Enable trusted watchdog interrupt as vIRQ in the secure side. */
	enable_trusted_wdog_interrupt(own_id, receiver_id);

	res = sp_twdog_map_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Send a message to the SP through direct messaging requesting it to
	 * start the trusted watchdog timer.
	 */
	res = sp_twdog_cmd_send(own_id, receiver_id, timer_ms);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void check_and_disable_trusted_wdog_timer(ffa_vm_id_t own_id,
						 ffa_vm_id_t receiver_id)
{
	struct ffa_value res;

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure Trusted Watchdog timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), IRQ_TWDOG_INTID);

	/* Disable Trusted Watchdog interrupt. */
	disable_trusted_wdog_interrupt(own_id, receiver_id);
}

/*
 * Test secure interrupt handling while the Secure Partition is in RUNNING
 * state.
 */
TEST(secure_interrupts, sp_running)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_vm_id_t receiver_id = service2_info->vm_id;

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 400);

	/* Send request to the SP to sleep. */
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME);

	/*
	 * Secure interrupt should trigger during this time, SP will handle the
	 * trusted watchdog timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

/*
 * Test secure interrupt handling while the Secure Partition is in WAITING
 * state.
 */
TEST(secure_interrupts, sp_waiting)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_vm_id_t receiver_id = service2_info->vm_id;
	uint64_t time1;
	volatile uint64_t time_lapsed;
	uint64_t timer_freq = read_msr(cntfrq_el0);

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 100);
	time1 = syscounter_read();

	/*
	 * Sleep for NS_SLEEP_TIME ms. This ensures secure wdog timer triggers
	 * during this time.
	 */
	waitms(NS_SLEEP_TIME);

	/* Lapsed time should be at least equal to sleep time. */
	time_lapsed = ((syscounter_read() - time1) * 1000) / timer_freq;

	EXPECT_GE(time_lapsed, NS_SLEEP_TIME);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

/*
 * Test secure interrupt handling while the Secure Partition is in BLOCKED
 * state.
 */
TEST(secure_interrupts, sp_blocked)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_vm_id_t receiver_id = service2_info->vm_id;
	const ffa_vm_id_t companion_id = service1_info->vm_id;

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 400);

	/*
	 * Send command to receiver SP to send command to companion SP to sleep
	 * there by putting receiver SP in BLOCKED state.
	 */
	res = sp_fwd_sleep_cmd_send(own_id, receiver_id, companion_id,
				    SP_SLEEP_TIME, false);

	/*
	 * Secure interrupt should trigger during this time, receiver SP will
	 * handle the trusted watchdog timer and sends direct response message.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

TEST(secure_interrupts, sp_preempted)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_vm_id_t receiver_id = service2_info->vm_id;

	gicv3_system_setup();
	interrupt_enable(PHYSICAL_TIMER_IRQ, true);
	interrupt_set_priority(PHYSICAL_TIMER_IRQ, 0x80);
	interrupt_set_edge_triggered(PHYSICAL_TIMER_IRQ, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();

	/* Set physical timer for 20 ms and enable. */
	write_msr(CNTP_TVAL_EL0, ns_to_ticks(20000000));
	write_msr(CNTP_CTL_EL0, CNTx_CTL_ENABLE_MASK);

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 200);

	/* Send request to receiver SP to sleep. */
	res = sp_sleep_cmd_send(own_id, receiver_id, 50);

	/* SP is pre-empted by the non-secure timer interrupt. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/* VM id/vCPU index are passed through arg1. */
	EXPECT_EQ(res.arg1, ffa_vm_vcpu(receiver_id, 0));

	/* Waiting for interrupt to be serviced in normal world. */
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Check that we got the interrupt. */
	EXPECT_EQ(last_interrupt_id, PHYSICAL_TIMER_IRQ);

	/* Check timer status. */
	EXPECT_EQ(read_msr(CNTP_CTL_EL0),
		  CNTx_CTL_ISTS_MASK | CNTx_CTL_ENABLE_MASK);

	/*
	 * NS Interrupt has been serviced and receiver SP is now in PREEMPTED
	 * state. Wait for trusted watchdog timer to be fired. SPMC queues
	 * the secure virtual interrupt.
	 */
	waitms(NS_SLEEP_TIME);

	/*
	 * Resume the SP to complete the busy loop, handle the secure virtual
	 * interrupt and return with success.
	 */
	res = ffa_run(ffa_vm_id(res), ffa_vcpu_index(res));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

/*
 * Test Secure Partition runs to completion if it specifies action in response
 * to Other-S Interrupt as queued.
 */
TEST(secure_interrupts, sp_other_s_interrupt_queued)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);

	/*
	 * Service2 SP is the target of trusted watchdog timer interrupt.
	 * Service3 SP specified action to Other-S Interrupt as queued.
	 */
	const ffa_vm_id_t target_id = service2_info->vm_id;
	const ffa_vm_id_t receiver_id = service3_info->vm_id;

	enable_trigger_trusted_wdog_timer(own_id, target_id, 400);

	/*
	 * Send command to receiver SP(Service3) to sleep for SP_SLEEP_TIME
	 * ms. Secure interrupt should trigger while SP is busy in running the
	 * sleep command. SPMC queues the virtual interrupt and resumes the
	 * SP.
	 */
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME);

	/* Service3 SP finishes and sends direct response back. */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Allocate cycles to target SP for it to handle the virtual secure
	 * interrupt.
	 */
	res = sp_sleep_cmd_send(own_id, target_id, 10);

	/*
	 * Secure interrupt should trigger during this time, SP will handle the
	 * trusted watchdog timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Check if the trusted watchdog timer interrupt has been handled.
	 */
	check_and_disable_trusted_wdog_timer(own_id, target_id);
}
