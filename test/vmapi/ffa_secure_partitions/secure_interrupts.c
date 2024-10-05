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

#include "ap_refclk_generic_timer.h"
#include "ffa_secure_partitions.h"
#include "gicv3.h"
#include "partition_services.h"
#include "sp_helpers.h"
#include "twdog.h"
#include "wdog.h"

#define SP_SLEEP_TIME 400U
#define NS_SLEEP_TIME 200U

#define LAST_SECONDARY_VCPU_ID (MAX_CPUS - 1)
#define MID_SECONDARY_VCPU_ID (MAX_CPUS / 2)

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
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME, 0);

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

/**
 * Test secure interrupt handling while the Secure Partition runs with
 * interrupts potentially masked. This test helps to validate the functionality
 * of the SPMC to intercept a direct response message sent via
 * FFA_MSG_SEND_DIRECT_RESP_32 if there are pending virtual secure interrupts
 * and reschedule the partition to handle the pending interrupt.
 */
TEST(secure_interrupts, sp_direct_response_intercepted)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 400);

	/* Send request to the SP to sleep uninterrupted. */
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME,
				OPTIONS_MASK_INTERRUPTS);

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

/**
 * Test secure interrupt handling while the Secure Partition runs with
 * interrupts potentially masked. This test helps to validate the functionality
 * of the SPMC to intercept a direct response message sent via
 * FFA_MSG_SEND_DIRECT_RESP2_64 if there are pending virtual secure interrupts
 * and reschedule the partition to handle the pending interrupt.
 */
TEST(secure_interrupts, sp_direct_response2_intercepted)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;
	const uint64_t msg[] = {SP_SLEEP_CMD, SP_SLEEP_TIME, 1};
	struct ffa_uuid uuid;

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 400);

	/* Send request to the SP to sleep uninterrupted. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	res = ffa_msg_send_direct_req2(own_id, receiver_id, &uuid,
				       (const uint64_t *)&msg, ARRAY_SIZE(msg));

	/*
	 * Secure interrupt should trigger during this time, SP will handle the
	 * trusted watchdog timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(res.arg5, SP_SLEEP_TIME);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

/*
 * This test is an extension of the 'sp_direct_response_intercepted' test. It
 * creates a scenario where a direct response message between two Secure
 * partitions in intercepted to signal a pending virtual secure interrupt.
 */
TEST(secure_interrupts, sp_forward_direct_response_intercepted)
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
	 * Send request to the companion SP to send command to receiver SP to
	 * sleep uninterrupted.
	 */
	res = sp_fwd_sleep_cmd_send(own_id, companion_id, receiver_id,
				    SP_SLEEP_TIME, OPTIONS_MASK_INTERRUPTS);

	/*
	 * Secure interrupt should trigger during this time, SP will handle the
	 * trusted watchdog timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

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
				    SP_SLEEP_TIME, 0);

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
	setup_wdog_timer_interrupt();

	/* Set watchdog timer for 20 ms*/
	start_wdog_timer(20);

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 200);

	/* Send request to receiver SP to sleep. */
	res = sp_sleep_cmd_send(own_id, receiver_id, 50, 0);

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
	EXPECT_EQ(last_interrupt_id, IRQ_WDOG_INTID);

	/* Stop the watchdog timer. */
	wdog_stop();

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

/**
 * Test to validate that an SPMC scheduled call chain cannot be preempted by a
 * non-secure interrupt.
 */
TEST(secure_interrupts, spmc_schedule_mode)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	gicv3_system_setup();
	setup_wdog_timer_interrupt();

	res = sp_prepare_spmc_call_chain_cmd_send(own_id, receiver_id, true);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 10);

	/* Set physical timer for 50 ms. */
	start_wdog_timer(50);

	/*
	 * Waiting for interrupt to be serviced in normal world. A non-zero
	 * value indicates the interrupt service routine has been executed
	 * upon delivery of interrupt to the CPU interface.
	 */
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Stop the watchdog timer. */
	wdog_stop();

	/* Check that we got the interrupt. */
	EXPECT_EQ(last_interrupt_id, IRQ_WDOG_INTID);

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
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME, 0);

	/* Service3 SP finishes and sends direct response back. */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Allocate cycles to target SP for it to handle the virtual secure
	 * interrupt.
	 */
	res = sp_sleep_cmd_send(own_id, target_id, 10, 0);

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

/**
 * Test that SPMC will queue secure virtual interrupt targeting an SP that
 * entered blocked state through FFA_YIELD and further signals the pending
 * virtual interrupt through FFA_INTERRUPT interface when target SP is resumed
 * by normal world through FFA_RUN.
 */
TEST(secure_interrupts, sp_blocked_through_ffa_yield)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 50);

	/* Send request to the SP to yield direct request. */
	res = sp_sleep_cmd_send(own_id, receiver_id, 0, OPTIONS_YIELD_DIR_REQ);
	EXPECT_EQ(res.func, FFA_YIELD_32);

	/*
	 * Sleep for 50 ms. This ensures secure wdog timer triggers during this
	 * time.
	 */
	waitms(50);

	/*
	 * Resume the SP to complete the busy loop and service the virtual
	 * interrupt.
	 */
	res = ffa_run(ffa_vm_id(res), ffa_vcpu_index(res));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);

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
	res = sp_sleep_cmd_send(own_id, args->receiver_id, SP_SLEEP_TIME, 0);
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

		cpu_id = hftest_get_cpu_id(i);
		args.vcpu_id = i;
		HFTEST_LOG("Booting CPU %u - %lx", i, cpu_id);

		EXPECT_EQ(hftest_cpu_start(
				  cpu_id, hftest_get_secondary_ec_stack(i),
				  cpu_entry_sp_sleep_loop, (uintptr_t)&args),
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
TEST_LONG_RUNNING(secure_interrupts, sp_route_interrupt_to_secondary_vcpu)
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

static void configure_generic_timer_interrupt(ffa_id_t source, ffa_id_t dest,
					      bool enable)
{
	struct ffa_value res;

	res = sp_virtual_interrupt_cmd_send(
		source, dest, IRQ_AP_REFCLK_BASE1_INTID, enable, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void enable_generic_timer_interrupt(ffa_id_t source, ffa_id_t dest)
{
	configure_generic_timer_interrupt(source, dest, true);
}

static void disable_generic_timer_interrupt(ffa_id_t source, ffa_id_t dest)
{
	configure_generic_timer_interrupt(source, dest, false);
}

static void enable_trigger_generic_timer(ffa_id_t own_id, ffa_id_t receiver_id,
					 uint32_t timer_ms)
{
	struct ffa_value res;

	/* Enable Generic Timer interrupt as vIRQ in the secure side. */
	enable_generic_timer_interrupt(own_id, receiver_id);

	/*
	 * Send a message to the SP through direct messaging requesting it to
	 * start the Generic Timer.
	 */
	res = sp_generic_timer_cmd_send(own_id, receiver_id, timer_ms);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void check_and_disable_generic_timer(ffa_id_t own_id,
					    ffa_id_t receiver_id)
{
	struct ffa_value res;

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure Generic Timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), IRQ_AP_REFCLK_BASE1_INTID);

	/* Disable Generic Timer interrupt. */
	disable_generic_timer_interrupt(own_id, receiver_id);
}

/**
 * Test handling of secure interrupt generated by Generic Timer.
 */
TEST(secure_interrupts, sp_running_generic_timer_interrupt)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	enable_trigger_generic_timer(own_id, receiver_id, 400);

	/* Send request to the SP to sleep. */
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME, 0);

	/*
	 * Secure interrupt should trigger during this time, SP will handle the
	 * generic timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

	check_and_disable_generic_timer(own_id, receiver_id);
}

/**
 * Test to validate SPMC can queue more than one pending virtual interrupt for
 * target vCPU of an SP. A NS interrupt causess the Service2 SP to be put in
 * preempted state thereby leading to queueing of virtual secure interrupts.
 * Two secure physical interrupts are used in this scenario to make SPMC queue
 * virtual interrupts, one from Trusted Watchtog timer and another from AP
 * REFCLK generic timer.
 */
TEST(secure_interrupts, sp_queue_virtual_interrupts)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	gicv3_system_setup();
	setup_wdog_timer_interrupt();

	/* Set watchdog timer for 20 ms*/
	start_wdog_timer(20);

	enable_trigger_generic_timer(own_id, receiver_id, 150);
	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 200);

	/* Send request to receiver SP to sleep. */
	res = sp_sleep_cmd_send(own_id, receiver_id, 50, 0);

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
	EXPECT_EQ(last_interrupt_id, IRQ_WDOG_INTID);

	/* Stop the watchdog timer. */
	wdog_stop();

	/*
	 * NS Interrupt has been serviced and receiver SP is now in PREEMPTED
	 * state. Wait for trusted watchdog timer and generic timer interrupt
	 * to be fired. SPMC queues the two secure virtual interrupts.
	 */
	waitms(NS_SLEEP_TIME);

	/*
	 * Resume the SP to complete the busy loop, handle the secure virtual
	 * interrupts and return with success.
	 */
	res = ffa_run(ffa_vm_id(res), ffa_vcpu_index(res));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}

static void cpu_entry_target_vcpu_waiting(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;
	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;

	assert(args->vcpu_count == 1);

	if (args->vcpu_id == LAST_SECONDARY_VCPU_ID) {
		const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777,
					0x88889999};

		/*
		 * One round of FFA_RUN is required execution contextx of
		 * secondary Secure Partitions.
		 */
		res = ffa_run(args->receiver_id, (ffa_vcpu_index_t)0);
		EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

		/*
		 * The direct request message makes the vcpu of target SP to
		 * migrate to this CPU i.e., last secondary CPU.
		 */
		enable_trigger_trusted_wdog_timer(own_id, args->receiver_id,
						  80);

		/*
		 * Sleep for 100 ms. This ensures secure wdog timer triggers
		 * during this time (on primary CPU) and SPMC queues the
		 * virtual interrupt for target vcpu.
		 */
		waitms(100);

		/*
		 * Send a dummy direct request message to target vcpu to give
		 * an opportunity for SPMC to signal the pending interrupt.
		 */
		res = sp_echo_cmd_send(own_id, args->receiver_id, msg[0],
				       msg[1], msg[2], msg[3]);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(res.arg4, msg[0]);
		EXPECT_EQ(res.arg5, msg[1]);
		EXPECT_EQ(res.arg6, msg[2]);
		EXPECT_EQ(res.arg7, msg[3]);

		/* Check for the last serviced secure virtual interrupt. */
		res = sp_get_last_interrupt_cmd_send(own_id, args->receiver_id);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp_value(res), IRQ_TWDOG_INTID);
	}

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

static void cpu_entry_target_vcpu_running(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;
	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;

	assert(args->vcpu_count == 1);

	if (args->vcpu_id == LAST_SECONDARY_VCPU_ID) {
		/*
		 * One round of FFA_RUN is required execution contextx of
		 * secondary Secure Partitions.
		 */
		res = ffa_run(args->receiver_id, (ffa_vcpu_index_t)0);
		EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

		/*
		 * The direct request message makes the vcpu of target SP to
		 * migrate to this CPU i.e., last secondary CPU.
		 */
		enable_trigger_trusted_wdog_timer(own_id, args->receiver_id,
						  80);

		/* Send request to the SP to sleep. */
		res = sp_sleep_cmd_send(own_id, args->receiver_id, 100, 0);

		/*
		 * Secure interrupt should trigger during this time, SP will
		 * handle the trusted watchdog timer interrupt.
		 */
		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);

		/* Check for the last serviced secure virtual interrupt. */
		res = sp_get_last_interrupt_cmd_send(own_id, args->receiver_id);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp_value(res), IRQ_TWDOG_INTID);
	}

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

static void cpu_entry_target_vcpu_blocked(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;
	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;

	assert(args->vcpu_count == 1);

	if (args->vcpu_id == LAST_SECONDARY_VCPU_ID) {
		/*
		 * One round of FFA_RUN is required execution contextx of
		 * secondary Secure Partitions.
		 */
		res = ffa_run(args->receiver_id, (ffa_vcpu_index_t)0);
		EXPECT_EQ(ffa_func_id(res), FFA_MSG_WAIT_32);

		/*
		 * The direct request message makes the vcpu of target SP to
		 * migrate to this CPU i.e., last secondary CPU.
		 */
		enable_trigger_trusted_wdog_timer(own_id, args->receiver_id,
						  80);

		/*
		 * Send command to target SP to send command to companion SP to
		 * sleep there by putting target SP's execution context in
		 * BLOCKED state.
		 */
		res = sp_fwd_sleep_cmd_send(own_id, args->receiver_id, SP_ID(1),
					    100, 0);

		/*
		 * Secure interrupt should trigger during this time, SP will
		 * handle the trusted watchdog timer interrupt.
		 */
		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);

		/* Check for the last serviced secure virtual interrupt. */
		res = sp_get_last_interrupt_cmd_send(own_id, args->receiver_id);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp_value(res), IRQ_TWDOG_INTID);
	}

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

static void run_test_secure_interrupt_targets_migrated_vcpu(
	void (*cpu_entry)(uintptr_t arg))
{
	struct ffa_value res;
	struct secondary_cpu_entry_args args = {.lock = SPINLOCK_INIT};
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *receiver_info = service2(mb.recv);
	ffa_id_t receiver_id = receiver_info->vm_id;

	args.receiver_id = receiver_id;
	args.vcpu_count = receiver_info->vcpu_count;

	if (args.vcpu_count > 1) {
		return;
	}

	/* Start secondary EC while holding lock. */
	sl_lock(&args.lock);

	for (ffa_vcpu_index_t i = 1; i < MAX_CPUS; i++) {
		uintptr_t cpu_id;

		cpu_id = hftest_get_cpu_id(i);
		args.vcpu_id = i;
		HFTEST_LOG("Booting CPU %u - %lx", i, cpu_id);

		EXPECT_EQ(hftest_cpu_start(cpu_id,
					   hftest_get_secondary_ec_stack(i),
					   cpu_entry, (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&args.lock);

		HFTEST_LOG("Done with CPU %u", i);
	}

	/* Send request to the SP to sleep. */
	res = sp_sleep_cmd_send(hf_vm_get_id(), receiver_id, SP_SLEEP_TIME, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

/**
 * Test to validate queueing of pending virtual interrupt targeting a vCPU in
 * waiting state after migrating to a secondary core.
 */
TEST_PRECONDITION_LONG_RUNNING(secure_interrupts, target_vcpu_migrated_waiting,
			       service2_is_up_sp)
{
	run_test_secure_interrupt_targets_migrated_vcpu(
		cpu_entry_target_vcpu_waiting);
}

/**
 * Test to validate queueing of pending virtual interrupt targeting a vCPU in
 * running state after migrating to a secondary core.
 */
TEST_PRECONDITION_LONG_RUNNING(secure_interrupts, target_vcpu_migrated_running,
			       service2_is_up_sp)
{
	run_test_secure_interrupt_targets_migrated_vcpu(
		cpu_entry_target_vcpu_running);
}

/**
 * Test to validate queueing of pending virtual interrupt targeting a vCPU in
 * blocked state after migrating to a secondary core.
 */
TEST_PRECONDITION_LONG_RUNNING(secure_interrupts, target_vcpu_migrated_blocked,
			       service2_is_up_sp)
{
	run_test_secure_interrupt_targets_migrated_vcpu(
		cpu_entry_target_vcpu_blocked);
}

/**
 * Test to validate SPMC can signal secure virtual interrupt to an SP that got
 * preempted while currently handling a virtual interrupt.
 */
TEST(secure_interrupts, preempt_interrupt_handling)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	res = sp_prepare_preempt_interrupt_handling_cmd_send(own_id,
							     receiver_id, true);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	configure_generic_timer_interrupt(own_id, receiver_id, true);
	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 1);
	waitms(5);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * After the SP services the trusted watchdog timer interrupt, it shall
	 * be resumed again by SPMC to signal generic timer interrupt.
	 */
	EXPECT_EQ(sp_resp_value(res), IRQ_AP_REFCLK_BASE1_INTID);

	/* Disable Generic Timer interrupt. */
	disable_generic_timer_interrupt(own_id, receiver_id);
}
