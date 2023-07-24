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
#include "hf/arch/vm/power_mgmt.h"
#include "hf/arch/vm/timer.h"

#include "ffa_secure_partitions.h"
#include "gicv3.h"
#include "partition_services.h"
#include "sp_helpers.h"

#define SP_SLEEP_TIME 400U
#define NS_SLEEP_TIME 200U

#define LAST_SECONDARY_VCPU_ID (MAX_CPUS - 1)
#define MID_SECONDARY_VCPU_ID (MAX_CPUS / 2)

alignas(4096) static uint8_t secondary_ec_stack[MAX_CPUS - 1][PAGE_SIZE];

struct secondary_cpu_entry_args {
	ffa_id_t receiver_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_vcpu_index_t vcpu_id;
	struct spinlock lock;
	ffa_vcpu_index_t target_vcpu_id;
};

static void configure_trusted_wdog_interrupt(ffa_id_t source, ffa_id_t dest,
					     bool enable)
{
	struct ffa_value res;

	res = sp_virtual_interrupt_cmd_send(source, dest, IRQ_TWDOG_INTID,
					    enable, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void enable_trusted_wdog_interrupt(ffa_id_t source, ffa_id_t dest)
{
	configure_trusted_wdog_interrupt(source, dest, true);
}

static void disable_trusted_wdog_interrupt(ffa_id_t source, ffa_id_t dest)
{
	configure_trusted_wdog_interrupt(source, dest, false);
}

static void enable_trigger_trusted_wdog_timer(ffa_id_t own_id,
					      ffa_id_t receiver_id,
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

static void check_and_disable_trusted_wdog_timer(ffa_id_t own_id,
						 ffa_id_t receiver_id)
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
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

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
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;
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
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;
	const ffa_id_t companion_id = service1_info->vm_id;

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
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

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
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);

	/*
	 * Service2 SP is the target of trusted watchdog timer interrupt.
	 * Service3 SP specified action to Other-S Interrupt as queued.
	 */
	const ffa_id_t target_id = service2_info->vm_id;
	const ffa_id_t receiver_id = service3_info->vm_id;

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

/*
 * Test that an SP can attempt to yield CPU cycles while handling secure
 * interrupt by invoking FFA_YIELD.
 */
TEST(secure_interrupts, sp_yield_sec_interrupt_handling)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;
	uint64_t time1;
	volatile uint64_t time_lapsed;
	uint64_t timer_freq = read_msr(cntfrq_el0);

	/*
	 * Send command to SP asking it attempt to yield cycles while handling
	 * secure interrupt.
	 */
	res = sp_yield_secure_interrupt_handling_cmd_send(own_id, receiver_id,
							  true);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 75);
	time1 = syscounter_read();

	/*
	 * Sleep for 100ms. This ensures secure wdog timer triggers
	 * during this time. SP starts handling secure interrupt but attempts
	 * to yields cycles. However, SPMC just resumes the SP to complete
	 * interrupt handling.
	 */
	waitms(100);

	/* Lapsed time should be at least equal to sleep time. */
	time_lapsed = ((syscounter_read() - time1) * 1000) / timer_freq;

	EXPECT_GE(time_lapsed, 100);

	res = sp_yield_secure_interrupt_handling_cmd_send(own_id, receiver_id,
							  false);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

static void cpu_entry_sp_sleep_loop(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;
	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;
	bool is_receiver_up_sp = args->vcpu_count == 1;

	/*
	 * Execution context(s) of secondary Secure Partitions need CPU cycles
	 * to be allocated through FFA_RUN interface to reach message loop.
	 */
	if (is_receiver_up_sp) {
		res = ffa_run(args->receiver_id, (ffa_vcpu_index_t)0);
	} else {
		res = ffa_run(args->receiver_id, args->vcpu_id);
	}

	EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

	/* Prepare for the trusted watchdog interrupt routed to target vCPU. */
	if (args->vcpu_id == args->target_vcpu_id) {
		res = sp_route_interrupt_to_target_vcpu_cmd_send(
			own_id, args->receiver_id, args->target_vcpu_id,
			IRQ_TWDOG_INTID);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);

		/*
		 * Make sure that twdog timer triggers shortly before the
		 * sleep duration ends.
		 */
		enable_trigger_trusted_wdog_timer(own_id, args->receiver_id,
						  SP_SLEEP_TIME - 50);
	}

	/* Send request to the SP to sleep. */
	res = sp_sleep_cmd_send(own_id, args->receiver_id, SP_SLEEP_TIME);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, args->receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Expect the target execution context of Service2 SP to handle the
	 * trusted watchdog interrupt succesfully.
	 */
	if (args->vcpu_id == args->target_vcpu_id) {
		EXPECT_EQ(sp_resp_value(res), IRQ_TWDOG_INTID);
	} else {
		/*
		 * Make sure Trusted Watchdog timer interrupt was not serviced
		 * by this execution context.
		 */
		EXPECT_NE(sp_resp_value(res), IRQ_TWDOG_INTID);
	}

	/* Clear last serviced secure virtual interrupt. */
	res = sp_clear_last_interrupt_cmd_send(own_id, args->receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

static void sp_route_interrupt_to_secondary_vcpu_base(
	struct secondary_cpu_entry_args args)
{
	/* Start secondary EC while holding lock. */
	sl_lock(&args.lock);

	for (ffa_vcpu_index_t i = 1; i < MAX_CPUS; i++) {
		uintptr_t cpu_id;
		ffa_vcpu_index_t hftest_cpu_index = MAX_CPUS - i;

		cpu_id = hftest_get_cpu_id(hftest_cpu_index);
		args.vcpu_id = i;
		HFTEST_LOG("Booting CPU %u - %x", i, cpu_id);

		EXPECT_EQ(hftest_cpu_start(cpu_id, secondary_ec_stack[i - 1],
					   sizeof(secondary_ec_stack[0]),
					   cpu_entry_sp_sleep_loop,
					   (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&args.lock);

		HFTEST_LOG("Done with CPU %u", i);
	}
}

/*
 * Test a Secure Partition can request the SPMC to reconfigure an interrupt to
 * be routed to a secondary vCPU.
 */
TEST(secure_interrupts, sp_route_interrupt_to_secondary_vcpu)
{
	struct secondary_cpu_entry_args args = {.lock = SPINLOCK_INIT};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	args.receiver_id = receiver_id;
	args.vcpu_count = service2_info->vcpu_count;

	/*
	 * Reconfigure the twdog interrupt to be routed to last secondary
	 * execution context of SP.
	 */
	args.target_vcpu_id = LAST_SECONDARY_VCPU_ID;
	sp_route_interrupt_to_secondary_vcpu_base(args);

	/*
	 * Reconfigure the twdog interrupt to be routed to mid secondary
	 * execution context of SP.
	 */
	args.target_vcpu_id = MID_SECONDARY_VCPU_ID;
	sp_route_interrupt_to_secondary_vcpu_base(args);
}
