/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/power_mgmt.h"

#include "vmapi/hf/call.h"

#include "gicv3.h"
#include "ipi_state.h"
#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/semaphore.h"
#include "twdog_state.h"
#include "wdog.h"

/**
 * Where the int_state struct is stored for the interrupt tests.
 * Used to track the IPI state across different threads in
 * different endpoints.
 */
alignas(PAGE_SIZE) static uint8_t interrupt_state_page[PAGE_SIZE];

/**
 * Structure defined for usage in tests with multiple cores.
 * Used to pass arguments from primary to secondary core.
 */
struct ipi_cpu_entry_args {
	ffa_id_t service_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_vcpu_index_t vcpu_id;
	ffa_vcpu_index_t target_vcpu_ids[MAX_CPUS];
	ffa_vcpu_count_t target_vcpu_count;
	struct mailbox_buffers mb;
	struct semaphore work_done;
};

/*
 * Test secure interrupt handling while the Secure Partition runs in FFA_RUN
 * partition runtime model with virtual interrupts potentially masked. This
 * test helps to validate the functionality of the SPMC, which is to:
 * - Intercept a FFA_MSG_WAIT invocation by the current SP in FFA_RUN partition
 *   runtime model, if there are pending virtual secure interrupts.
 * - Resume the SP to handle the pending secure virtual interrupt.
 *
 * For orchestrating the above scenario, we leverage indirect messaging
 * interface and allocate CPU cycles to the Secure Partition through FFA_RUN
 * interface.
 */
TEST_PRECONDITION(secure_interrupts, preempted_by_secure_interrupt,
		  service1_is_not_vm)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const uint32_t delay = 100;
	uint32_t echo_payload;
	ffa_id_t echo_sender;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "sec_interrupt_preempt_msg",
		       mb.send);

	/*
	 * Send an indirect message to convey the Secure Watchdog timer delay
	 * which serves as the source of the secure interrupt.
	 */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &delay, sizeof(delay), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Schedule message receiver through FFA_RUN interface. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	echo_sender = receive_indirect_message(&echo_payload,
					       sizeof(echo_payload), mb.recv)
			      .sender;

	HFTEST_LOG("Message echoed back: %#x", echo_payload);
	EXPECT_EQ(echo_payload, delay);
	EXPECT_EQ(echo_sender, service1_info->vm_id);
}

/**
 * This test expects SP1 to have pended an interrupt for SP2, before SP2 has
 * booted, following the boot protocol.
 *
 * TODO: Make this test applicable to S-EL0 and S-EL1 UP partitions.
 */
TEST_PRECONDITION(secure_interrupts, handle_interrupt_rtm_init,
		  service2_is_mp_sp)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service2_info->vm_id, "check_interrupt_rtm_init_handled",
		       mb.send);

	/* Schedule message receiver through FFA_RUN interface. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * Test that SPMC will queue secure virtual interrupt targeting an SP that
 * entered blocked state through FFA_YIELD while processing a direct request
 * from a companion SP. This test also further ensures that SPMC signals the
 * pending virtual interrupt through FFA_INTERRUPT interface when target SP is
 * resumed by companion SP through FFA_RUN.
 */
TEST(secure_interrupts, sp_to_sp_yield_interrupt_queued)
{
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *target_info = service1(mb.recv);
	struct ffa_partition_info *companion_info = service2(mb.recv);
	struct ffa_value ret;
	ffa_id_t memory_receivers[] = {
		target_info->vm_id,
		companion_info->vm_id,
	};

	SERVICE_SELECT(target_info->vm_id, "yield_direct_req_service_twdog_int",
		       mb.send);

	/* Schedule the target SP through FFA_RUN interface. */
	ret = ffa_run(target_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	SERVICE_SELECT(companion_info->vm_id,
		       "send_direct_req_yielded_and_resumed", mb.send);

	/*
	 * Send an indirect message to convey the target SP responsible for
	 * handling the secure interrupt from trusted watchdog timer.
	 */
	ret = send_indirect_message(own_id, companion_info->vm_id, mb.send,
				    &(target_info->vm_id),
				    sizeof(target_info->vm_id), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Schedule companion SP through FFA_RUN interface. */
	ret = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Share memory used for interrupt status coordination and initialize
	 * the state.
	 */
	hftest_twdog_state_share_page_and_init((uint64_t)interrupt_state_page,
					       memory_receivers, 2, mb.send);

	ret = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	ret = ffa_run(target_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Allow companion SP to initiate a direct request to target SP. */
	ret = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	ASSERT_TRUE(hftest_twdog_state_is(HANDLED));
}

/**
 * Setups up SRI and returns the interrupt ID.
 */
uint32_t enable_sri(void)
{
	struct ffa_value ret;
	uint32_t sri_id;

	dlog_verbose("Enabling the SRI");

	ret = ffa_features(FFA_FEATURE_SRI);

	sri_id = ffa_feature_intid(ret);

	interrupt_enable(sri_id, true);
	interrupt_set_priority(sri_id, 0x10);
	interrupt_set_edge_triggered(sri_id, false);
	interrupt_set_priority_mask(0xff);

	arch_irq_enable();

	return sri_id;
}

static void setup_wdog_timer_interrupt(void)
{
	interrupt_enable(IRQ_WDOG_INTID, true);
	interrupt_set_priority(IRQ_WDOG_INTID, 0x80);
	interrupt_set_edge_triggered(IRQ_WDOG_INTID, true);
	interrupt_set_priority_mask(0xff);
	arch_irq_enable();
}

static void start_wdog_timer(uint32_t time_ms)
{
	HFTEST_LOG("Starting wdog timer\n");
	wdog_start((time_ms * ARM_SP805_WDOG_CLK_HZ) / 1000);
}

static void check_wdog_timer_interrupt_serviced(void)
{
	uint64_t rdist_addr = interrupt_get_gic_rdist_addr();
	io32_t gicr_ispendr0 = IO32_C(rdist_addr + GICR_ISPENDR0);
	io32_t gicr_isactiver0 = IO32_C(rdist_addr + GICR_ISACTIVER0);

	/* Waiting for interrupt to be serviced in normal world. */
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(gicr_ispendr0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(gicr_isactiver0), 0);
	}
	/* Check that we got the interrupt. */
	HFTEST_LOG("Checking for interrupt\n");
	EXPECT_EQ(last_interrupt_id, IRQ_WDOG_INTID);
	/* Stop the watchdog timer. */
	wdog_stop();
	/* There should again be no pending or active interrupts. */
	EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
	EXPECT_EQ(io_read32(gicr_ispendr0), 0);
	EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
	EXPECT_EQ(io_read32(gicr_isactiver0), 0);
}

/**
 * Secondary CPU entrypoint.
 * Requests the 'send_ipi' function in the designated FF-A endpoint.
 * Sends the vCPU to be targeted by the IPI via indirect messaging.
 */
static void cpu_entry_send_ipi(uintptr_t arg)
{
	struct ipi_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct ipi_cpu_entry_args *)arg;
	struct ffa_value ret;
	const ffa_id_t own_id = hf_vm_get_id();
	ffa_vcpu_index_t target_vcpu_ids[MAX_CPUS];

	ASSERT_TRUE(args != NULL);
	ASSERT_TRUE(args->vcpu_count > 1);
	ASSERT_TRUE(args->target_vcpu_count > 0 &&
		    args->target_vcpu_count < MAX_CPUS);

	/*
	 * Populate the target_vcpus ID. To prevent sending a count with the
	 * array of target vCPU IDs set any unused fields to an invalid ID
	 * (MAX_CPUS).
	 */
	for (int i = 0; i < args->target_vcpu_count; i++) {
		target_vcpu_ids[i] = args->target_vcpu_ids[i];
	}
	for (int i = args->target_vcpu_count; i < MAX_CPUS; i++) {
		target_vcpu_ids[i] = MAX_CPUS;
	}

	SERVICE_SELECT_MP(args->service_id, "send_ipi", args->mb.send,
			  args->vcpu_id);

	/* Run service. */
	ret = ffa_run(args->service_id, args->vcpu_id);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send it the target vCPU ID. */
	ret = send_indirect_message(own_id, args->service_id, args->mb.send,
				    target_vcpu_ids, sizeof(target_vcpu_ids),
				    0);

	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(args->service_id, args->vcpu_id).func, FFA_YIELD_32);

	/* Signal to primary core that test is complete.*/
	semaphore_signal(&args->work_done);

	arch_cpu_stop();
}

/**
 * Test that Service1 can send IPI to vCPU0 from vCPU1, whilst vCPU0 is in
 * running state.
 * Test Sequence:
 * - Bootstrap vCPU0 in the respective test service, such that it can initialise
 *   the IPI state.
 * - Service1 vCPU0 terminates and leaves the IPI state not READY.
 * - Start CPU1 and within it, invoke test service to send IPI. Test service
 * waits for state machine to transition into READY state.
 * - Resume Service1 vCPU0 such that it can set IPI state to READY.
 *
 * Failure in this test would be captured by timeout as Service1 vCPU0 would
 * hang waiting for the IPI.
 */
TEST_PRECONDITION(ipi, receive_ipi_running_vcpu, service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0};

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_running", mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share memory to setup the IPI state structure. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));

	/*
	 * Resumes service1 in target vCPU0 so it sets IPI state to READY and
	 * handles IPI.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);
}

/*
 * Test that secure interrupts do not interfere with the receipt of IPIs and
 * vice versa. Test Sequence:
 * - Bootstrap vCPU0 in the respective test service, such that it can initialise
 *   the IPI state.
 * - Service1 vCPU0 terminates and leaves the IPI state not READY.
 * - Start CPU1 and within it, invoke test service to send IPI. Test service
 * waits for state machine to transition into READY state.
 * - Resume Service1 vCPU0 such that it can set IPI state to READY.
 *
 * Failure in this test would be captured by timeout as Service1 vCPU0 would
 * hang waiting for the IPI.
 */
TEST_PRECONDITION(ipi, receive_ipi_running_vcpu_with_secure_interrupts,
		  service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0};

	SERVICE_SELECT(service1_info->vm_id,
		       "receive_ipi_running_with_secure_interrupts", mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share memory to setup the IPI state structure. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));

	/*
	 * Resumes service1 in target vCPU0 so it sets IPI state to READY and
	 * handles IPI.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);
}

/**
 * Test that a service cannot target an IPI to it's own vCPU or an invalid vCPU
 * ID.
 */
TEST_PRECONDITION(ipi, receive_ipi_invalid_target_vcpus, service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;
	const ffa_id_t own_id = hf_vm_get_id();
	ffa_vcpu_index_t target_vcpu_id = 0;

	SERVICE_SELECT(service1_info->vm_id, "send_ipi_fails", mb.send);

	/* Run service. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send service it's own vCPU index. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &target_vcpu_id, sizeof(target_vcpu_id), 0);

	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	target_vcpu_id = MAX_CPUS;
	/* Send service an out of bounds vCPU index. */
	ret = send_indirect_message(own_id, service1_info->vm_id, mb.send,
				    &target_vcpu_id, sizeof(target_vcpu_id), 0);

	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);
}

/**
 * Helper to run the test sequence for the NWd waiting tests.
 * Test Sequence:
 * - Bootstrap the target CPU (current CPU) and share memory with it to
 *   instanciate the IPI state. The vCPU terminates with FFA_MSG_WAIT,
 *   so it is in the waiting state.
 * - Start the sending CPU (specified in the sender_cpu_entry_args)
 *   and within it, invoke test service to send IPI. Test service
 *   waits for state machine to transition into READY state.
 * - NWd waits for the Schedule Reciever Interrupt, checks that the target vCPU
 *   is reported by FFA_NOTIFICATION_INFO_GET as having an IPI pending
 *   and then runs it to handle the IPI.
 * - The target vCPU is resumed to handle the IPI virtual interrupt. It should
 * attest state transitions into HANDLED from the interrupt handler.
 */
static void ipi_nwd_waiting_test(
	ffa_vcpu_index_t vcpu_id,
	struct ipi_cpu_entry_args *sender_cpu_entry_args)
{
	ffa_id_t service_id = sender_cpu_entry_args->service_id;
	struct mailbox_buffers mb = sender_cpu_entry_args->mb;
	ffa_id_t memory_receivers[] = {
		service_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0};
	struct ffa_value ret;
	uint32_t sri_id;
	ffa_vcpu_count_t target_vcpu_count =
		sender_cpu_entry_args->target_vcpu_count;
	uint32_t expected_list_count = 0;
	uint32_t expected_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {
		0xFFFF};
	uint16_t expected_ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0xFFFF};

	HFTEST_LOG("IPI Waiting in NWd test from CPU %d to CPU %d\n",
		   sender_cpu_entry_args->vcpu_id, vcpu_id);

	gicv3_system_setup();

	/* Get ready to handle SRI.  */
	sri_id = enable_sri();

	SERVICE_SELECT_MP(service_id, "receive_ipi_waiting_vcpu", mb.send,
			  vcpu_id);

	ret = ffa_run(service_id, vcpu_id);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share memory to setup the IPI state structure. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, vcpu_id);

	EXPECT_EQ(ffa_run(service_id, vcpu_id).func, FFA_MSG_WAIT_32);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(sender_cpu_entry_args->vcpu_id),
		hftest_get_secondary_ec_stack(sender_cpu_entry_args->vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)sender_cpu_entry_args));

	/*
	 * Reset the last interrupt ID so we know the next SRI is relate to
	 * the IPI handling.
	 */
	last_interrupt_id = 0;

	/*
	 * Set the state to READY such that vCPU1 injects IPI to target vCPU0.
	 */
	hftest_ipi_state_set_all_ready();

	/* Wait for the SRI. */
	while (last_interrupt_id != sri_id) {
		interrupt_wait();
	}

	/* Check the target vCPUs are returned by FFA_NOTIFICATION_INFO_GET. */
	for (; expected_list_count <
	       target_vcpu_count / FFA_NOTIFICATIONS_LIST_MAX_VCPU_IDS;
	     expected_list_count++) {
		expected_lists_sizes[expected_list_count] =
			FFA_NOTIFICATIONS_LIST_MAX_VCPU_IDS;
	}
	expected_lists_sizes[expected_list_count++] =
		target_vcpu_count % FFA_NOTIFICATIONS_LIST_MAX_VCPU_IDS;
	for (uint32_t i = 0; i < target_vcpu_count + expected_list_count; i++) {
		/*
		 * Every 4th element we start a new list so must specifiy the
		 * service id again.
		 */
		if (i % FFA_NOTIFICATIONS_LIST_MAX_SIZE == 0) {
			expected_ids[i] = service_id;
		} else {
			ffa_vcpu_index_t index_without_service_ids =
				i - ((i / FFA_NOTIFICATIONS_LIST_MAX_SIZE) + 1);
			expected_ids[i] = sender_cpu_entry_args->target_vcpu_ids
						  [index_without_service_ids];
		}
	}

	ffa_notification_info_get_and_check(expected_list_count,
					    expected_lists_sizes, expected_ids);

	/* Resumes service on target vCPU to handle IPI. */
	ret = ffa_run(service_id, vcpu_id);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * Test that Service1 can send IPI to vCPU0 from vCPU1, whilst vCPU0 is in
 * waiting state and execution is in the normal world.
 */
TEST_PRECONDITION(ipi, receive_ipi_waiting_vcpu_in_nwd, service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};

	ipi_nwd_waiting_test(0, &vcpu1_args);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);
}

/*
 * CPU entry function to run the IPI waiting test sequence.
 */
static void cpu_entry_receive_ipi_waiting(uintptr_t arg)
{
	struct ipi_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct ipi_cpu_entry_args *)arg;
	struct ipi_cpu_entry_args sender_vcpu_args = {
		.service_id = args->service_id,
		.vcpu_count = args->vcpu_count,
		.vcpu_id = args->vcpu_id + 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = args->target_vcpu_count,
		.mb = args->mb};

	assert(args->vcpu_id < MAX_CPUS - 1);
	assert(args->target_vcpu_count < MAX_CPUS);

	for (int i = 0; i < args->target_vcpu_count; i++) {
		sender_vcpu_args.target_vcpu_ids[i] = args->target_vcpu_ids[i];
	}

	ipi_nwd_waiting_test(args->vcpu_id, &sender_vcpu_args);

	semaphore_signal(&args->work_done);
}

/**
 * Test that Service1 can send IPI to vCPU1 from vCPU2, whilst vCPU1 is in
 * waiting state and execution is in the normal world.
 */
TEST_PRECONDITION(ipi, receive_ipi_waiting_vcpu_in_nwd_non_primary_cpu,
		  service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	for (size_t i = 1; i < MAX_CPUS - 1; i += 2) {
		struct ipi_cpu_entry_args receiver_vcpu_args = {
			.service_id = service1_info->vm_id,
			.vcpu_count = service1_info->vcpu_count,
			.vcpu_id = i,
			.target_vcpu_ids = {i},
			.target_vcpu_count = 1,
			.mb = mb};

		/* Initalize semaphores to sync primary and secondary cores. */
		semaphore_init(&receiver_vcpu_args.work_done);
		/* Bring-up the core that receives the IPI. */
		ASSERT_TRUE(hftest_cpu_start(
			hftest_get_cpu_id(receiver_vcpu_args.vcpu_id),
			hftest_get_secondary_ec_stack(
				receiver_vcpu_args.vcpu_id),
			cpu_entry_receive_ipi_waiting,
			(uintptr_t)&receiver_vcpu_args));

		semaphore_wait(&receiver_vcpu_args.work_done);
		hftest_ipi_state_reset_all();
	}
}

/*
 * Test that IPIs and NWd interrupts don't interfere with each other.
 * Trigger a NWd interrupt using the watchdog, once received run the
 * usual IPI waiting workload. Then once again trigger a NWd interrupt.
 * All should be recieved as normal.
 */
TEST_PRECONDITION(ipi, receive_ipi_waiting_vcpu_in_nwd_with_nwd_interrupt,
		  service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};

	gicv3_system_setup();
	setup_wdog_timer_interrupt();

	last_interrupt_id = 0;

	start_wdog_timer(20);

	check_wdog_timer_interrupt_serviced();

	ipi_nwd_waiting_test(0, &vcpu1_args);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);

	last_interrupt_id = 0;

	start_wdog_timer(20);

	check_wdog_timer_interrupt_serviced();
}

/**
 * Test that Service1 can send IPI to vCPU0 from vCPU1, whilst vCPU0 is in
 * waiting state and execution is in the secure world. Service2 is given access
 * to a shared buffer, where Service1 would have instanciated the IPI state. At
 * the appropriate timing, Service2 transitions IPI state into READY.
 *
 * Test Sequence:
 * - Bootstrap vCPU0 and share memory with it to instanciate the IPI state. The
 *   vCPU0 terminates with FFA_MSG_WAIT, so it is in the waiting state.
 * - Bootstrap Service2 vCPU0 in 'set_ipi_ready'. This gives it access to the
 *   IPI state.
 * - Start CPU1 and within it, invoke test service to send IPI. Test service
 *   waits for state machine to transition into READY state.
 * - Resume Service2 vCPU0 so execution is in the Secure World. At this point,
 *   Service2 transitions IPI state to READY, and waits for the IPI state to be
 *   Handled.
 * - NWd vCPU0 is resumed by the Schedule Reciever Interrupt checks that
 *   Service1 vCPU0 is reported by FFA_NOTIFICATION_INFO_GET as having an IPI
 *   pending, and then runs Service1 vCPU0 to handle the IPI.
 * - Service1 vCPU0 is resumed to handle the IPI virtual interrupt.
 *   It should attest state transitions into HANDLED from the interrupt handler.
 * - Service2 vCPU0 is then run to check that it successfully runs and completes
 *   after being interrupted.
 */
TEST_PRECONDITION(ipi, receive_ipi_waiting_vcpu_in_swd, service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
		service2_info->vm_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0, 0};
	uint32_t sri_id;
	uint32_t expected_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint16_t expected_ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};

	gicv3_system_setup();

	/* Get ready to handle SRI.  */
	sri_id = enable_sri();

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);

	/* Service1 is to handle the IPI in vCPU0. */
	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_waiting_vcpu",
		       mb.send);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	SERVICE_SELECT(service2_info->vm_id, "set_ipi_ready", mb.send);
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	/* Run the services so they can enter the waiting state. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));

	/*
	 * Reset the last interrupt ID so we know the next SRI is relate to
	 * the IPI handling.
	 */
	last_interrupt_id = 0;

	/*
	 * Resume service2 to set IPI state to ready, and cause service1 in
	 * vCPU1 to send the IPI.
	 */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_INTERRUPT_32);

	/* Wait for the SRI. */
	while (last_interrupt_id != sri_id) {
		interrupt_wait();
	}

	/* Check the target vCPU 0 is returned by FFA_NOTIFICATION_INFO_GET. */
	expected_lists_sizes[0] = 1;
	expected_ids[0] = service1_info->vm_id;
	expected_ids[1] = 0;

	ffa_notification_info_get_and_check(1, expected_lists_sizes,
					    expected_ids);

	/* Resumes service1 in target vCPU 0 to handle IPI. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);

	/*
	 * Resume service2 to check it can run to completion after being
	 * interrupted.
	 */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);
}

/**
 * Test that Service1 can send IPI to vCPU0 from vCPU1, whilst vCPU0 is in
 * preempted state. The Normal World configures the watchdog timer,
 * to trigger a NS interrupt. When handling the interrupt, the PVM sets
 * IPI state to ready, and resumes service1 to handle the IPI.
 *
 * Test Sequence:
 * - Bootstrap vCPU0 and share memory with it to instanciate the IPI state.
 * - Start CPU1 and within it, invoke test service to send IPI. Test service
 * waits for state machine to transition into READY state.
 * - Configure the watchdog timer to trigger NS interrupt.
 * - Resume service1 at vCPU0. It shall wait for the IPI to be handled. While
 *   in this loop, the NS interrupt will fire and leave it in a preempted state.
 * - PVM is executed, handles timer interrupt, sets IPI state to READY, and
 * resumes service1 vCPU0 to handle the IPI.
 * - Service1 vCPU0 is resumed to handle the IPI VI. It should attest state
 * transitions into HANDLED from the interrupt handler.
 */
TEST_PRECONDITION(ipi, receive_ipi_preempted_vcpu, service1_is_mp_sp)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0};

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_preempted_or_blocked",
		       mb.send);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	/* Setting buffer to control the IPI state. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	/* Run the service so it can enter the blocked state. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));

	/* Configure GIC and setup the watchdog timer. */
	gicv3_system_setup();
	setup_wdog_timer_interrupt();

	start_wdog_timer(20);

	/*
	 * Resumes service1 in target vCPU0 so it sets IPI state to READY and
	 * handles IPI.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_INTERRUPT_32);

	check_wdog_timer_interrupt_serviced();

	/*
	 * The target vCPU should be in preempted state at this stage.
	 * As such, signal the state machine that the "send_ipi" service
	 * can invoke the 'hf_interrupt_send_ipi' interface.
	 */
	hftest_ipi_state_set_all_ready();

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);
}

/**
 * Test that Service1 can send IPI to vCPU0 from vCPU1, whilst vCPU0 is in
 * blocked state.
 *
 * Test Sequence:
 * - Bootstrap vCPU0 and share memory with it to instantiate the IPI state.
 * - After setting the IPI state, Service1 should use FFA_YIELD to relinquish
 *   cycles back to the normal world. This should leave the vCPU0 in blocked
 *   state.
 * - Start CPU1 and within it, invoke test service's vCPU1 to send IPI to vCPU0.
 *   Test service waits for state machine to transition into READY state.
 * - PVM sets IPI state to READY, and resumes service1 vCPU0 to handle the
 *   IPI.
 * - Service1 vCPU0 is resumed to handle the IPI virtual interrupt.
 *   It should attest state transitions into HANDLED from the interrupt handler.
 */
TEST_PRECONDITION(ipi, receive_ipi_blocked_vcpu, service1_is_mp_sp)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {service1_info->vm_id};
	uint32_t receivers_ipi_state_indexes[] = {0};

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_preempted_or_blocked",
		       mb.send);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	/* Setting buffer to control the IPI state. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	/* Run the service so it can enter the blocked state. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));

	/*
	 * The target vCPU should be in blocked state at this stage.
	 * As such, signal the state machine that the "send_ipi" service
	 * can invoke the 'hf_interrupt_send_ipi' interface.
	 */
	hftest_ipi_state_set_all_ready();

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&vcpu1_args.work_done);
}

/*
 * Test that if Service1 and Service2 send IPI to target vCPUs, in the waiting
 * state, on the same physical CPU both target vCPUs are delivered the IPI.
 * Test Sequence:
 * - Initalize the GIC so that the SRI can be received later in the test.
 * - Bootstrap vCPU0 Service2 to run receiver_ipi_waiting_vcpu test service.
 * - Initialize and share the memory for the IPI state. Send each service
 *   an index of the IPI state array to use, for test coordination.
 * - Start CPU1 and within it, invoke Service1 to send IPI. Test service waits
 *   for state machine to transition into READY state.
 * - Start CPU2 and within it, invoke Service2 to send IPI. Test service waits
 *   for state machine to transition into READY state.
 * - NWd sets the states for each service to READY. Waits for the
 *   Schedule Reciever Interrupts (SRIs). This may come as 2 separate SRIs for
 *   each IPI or togather. Using the lists_count given by
 *   FFA_NOTIFICATION_INFO_GET the number of SRIs can be found. Then the
 *   remaining fields returned can be validated.
 * - Resume Service1 and Service2 vCPU0 such that they can handle the IPI
 *   virtual interrupt. It should check the IPI state for the service is now
 *   HANDLED from the interrupt handler.
 *
 * Failure in this test would be captured by timeout as Service1 or Service2
 * vCPU0 would hang waiting for the IPI.
 */
TEST_PRECONDITION(ipi, receive_ipi_multiple_services_to_same_cpu_waiting,
		  service1_and_service2_are_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_value ret;
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	struct ipi_cpu_entry_args vcpu2_args = {
		.service_id = service2_info->vm_id,
		.vcpu_count = service2_info->vcpu_count,
		.vcpu_id = 2,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
		service2_info->vm_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0, 1};
	uint32_t sri_id;
	uint16_t notif_vm_id;

	gicv3_system_setup();
	/* Get ready to handle SRI. */
	sri_id = enable_sri();

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_waiting_vcpu",
		       mb.send);
	SERVICE_SELECT(service2_info->vm_id, "receive_ipi_waiting_vcpu",
		       mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share memory to setup the IPI state structure. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	/* Run the services so they enter the waiting state. */
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);
	semaphore_init(&vcpu2_args.work_done);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu2_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu2_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu2_args));

	/*
	 * Reset the last interrupt ID so we know the next SRI is relate to
	 * the IPI handling.
	 */
	last_interrupt_id = 0;
	/*
	 * Set the state to READY such that vCPU1 and vCPU2 inject IPI to target
	 * vCPU0.
	 */
	hftest_ipi_state_set_all_ready();

	while (last_interrupt_id != sri_id) {
		interrupt_wait();
	}
	last_interrupt_id = 0;

	ret = ffa_notification_info_get();

	EXPECT_EQ(ret.func, FFA_SUCCESS_64);
	uint32_t lists_count = ffa_notification_info_get_lists_count(ret);

	/* Depending on the timings the the SRI could cover one or both of the
	 * IPIs. */
	if (lists_count == 1) {
		EXPECT_EQ(ffa_notification_info_get_list_size(ret, 1), 1);
		notif_vm_id = ret.arg3 & 0xFFFF;
		EXPECT_TRUE(notif_vm_id == service1_info->vm_id ||
			    notif_vm_id == service2_info->vm_id);
		EXPECT_EQ(ret.arg3 >> 16 & 0xFFFF, 0);

		/* Wait for the second SRI. */
		while (last_interrupt_id != sri_id) {
			interrupt_wait();
		}
		ret = ffa_notification_info_get();

		EXPECT_EQ(ret.func, FFA_SUCCESS_64);

		EXPECT_EQ(ffa_notification_info_get_list_size(ret, 1), 1);
		notif_vm_id = ret.arg3 & 0xFFFF;
		EXPECT_TRUE(notif_vm_id == service1_info->vm_id ||
			    notif_vm_id == service2_info->vm_id);
		EXPECT_EQ(ret.arg3 >> 16 & 0xFFFF, 0);
	} else if (lists_count == 2) {
		EXPECT_EQ(ffa_notification_info_get_list_size(ret, 1), 1);
		notif_vm_id = ret.arg3 & 0xFFFF;
		EXPECT_TRUE(notif_vm_id == service1_info->vm_id ||
			    notif_vm_id == service2_info->vm_id);
		EXPECT_EQ(ret.arg3 >> 16 & 0xFFFF, 0);
		EXPECT_EQ(ffa_notification_info_get_list_size(ret, 2), 1);
		notif_vm_id = ret.arg4 & 0xFFFF;
		EXPECT_TRUE(notif_vm_id == service1_info->vm_id ||
			    notif_vm_id == service2_info->vm_id);
		EXPECT_EQ(ret.arg4 >> 16 & 0xFFFF, 0);
	} else {
		/* We shouldn't be here so this expect will fail. */
		panic("Invalid lists count.\n");
	}

	/* Resumes service1 in target vCPU 0 to handle IPI. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
	/* Resumes service2 in target vCPU 0 to handle IPI. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/*
 * Test that if Service1 sends an IPI to a running vCPU and Service2 sends
 * and IPI to a waiting vCPU on the same physical CPU both witll receive the
 * IPI.
 * Test Sequence:
 * - Initalize the GIC so that the SRI can be received later in the test.
 * - Bootstrap vCPU0 Service1 to run the receive_ipi_running test service
 *   and Service2 to run the receiver_ipi_waiting_vcpu test service.
 * - Initialize and share the memory for the IPI state. Send each service
 *   an index of the IPI state array to use, for test coordination.
 * - Start CPU1 and within it, invoke Service1 to send IPI. Test service waits
 *   for state machine to transition into READY state.
 * - Start CPU2 and within it, invoke Service2 to send IPI. Test service waits
 *   for state machine to transition into READY state.
 * - Run Service1, the test service will set the IPI state for all services to
 *   READY. Service1 should recieve the IPI state handle it (mark IPI state as
 *   HANDLED) and yield.
 * - NWd waits to receive the SRI SGI. Once it does it checks that Service2
 *   vCPU0 is reported but FFA_NOTIFICATION_INFO_GET as having an IPI pending.
 *   It then runs Service2 vCPU0 to handle the IPI.
 * - Service2 vCPU0 resumes, handles the IPI (marks IPI state as HANDLED) and
 *   yields.
 */
TEST_PRECONDITION(ipi, receive_ipi_multiple_services_to_same_cpu_running,
		  service1_and_service2_are_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_value ret;
	struct ipi_cpu_entry_args vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	struct ipi_cpu_entry_args vcpu2_args = {
		.service_id = service2_info->vm_id,
		.vcpu_count = service2_info->vcpu_count,
		.vcpu_id = 2,
		.target_vcpu_ids = {0},
		.target_vcpu_count = 1,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
		service2_info->vm_id,
	};

	uint32_t receivers_ipi_state_indexes[] = {0, 1};
	uint32_t sri_id;
	uint32_t expected_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint16_t expected_ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};

	gicv3_system_setup();
	/* Get ready to handle SRI. */
	sri_id = enable_sri();

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_running", mb.send);
	SERVICE_SELECT(service2_info->vm_id, "receive_ipi_waiting_vcpu",
		       mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share memory to setup the IPI state structure. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_YIELD_32);
	/* Run the services so they enter the waiting state. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);
	semaphore_init(&vcpu2_args.work_done);

	/* Bring-up the core that sends the IPI. */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu1_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu1_args));
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(vcpu2_args.vcpu_id),
		hftest_get_secondary_ec_stack(vcpu2_args.vcpu_id),
		cpu_entry_send_ipi, (uintptr_t)&vcpu2_args));

	/*
	 * Reset the last interrupt ID so we know the next SRI is relate to
	 * the IPI handling.
	 */
	last_interrupt_id = 0;
	/*
	 * Run service1 which will set the ready state for both service1
	 * and service2.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Wait for the SRI. */
	while (last_interrupt_id != sri_id) {
		interrupt_wait();
	}

	/* Check the target vCPU 0 is returned by FFA_NOTIFICATION_INFO_GET. */
	expected_lists_sizes[0] = 1;
	expected_ids[0] = service2_info->vm_id;
	expected_ids[1] = 0;
	ffa_notification_info_get_and_check(1, expected_lists_sizes,
					    expected_ids);

	/* Resumes service2 in target vCPU 0 to handle IPI. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	semaphore_wait(&vcpu1_args.work_done);
	semaphore_wait(&vcpu2_args.work_done);
}

/*
 * Check that a single service can send an IPI to two vCPUs and both
 * successfully recieve it.
 */
TEST_PRECONDITION(ipi, receive_ipi_one_service_to_two_vcpus, service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_value ret;
	struct ipi_cpu_entry_args receiver_vcpu1_args = {
		.service_id = service1_info->vm_id,
		.vcpu_count = service1_info->vcpu_count,
		.vcpu_id = 1,
		.target_vcpu_ids = {0, 1},
		.target_vcpu_count = 2,
		.mb = mb};
	ffa_id_t memory_receivers[] = {
		service1_info->vm_id,
	};
	uint32_t receivers_ipi_state_indexes[] = {0};

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_waiting_vcpu",
		       mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share memory to setup the IPI state structure. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_MSG_WAIT_32);

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&receiver_vcpu1_args.work_done);

	last_interrupt_id = 0;

	/*
	 * Bring-up another core to also receive the IPI. Test coorindation will
	 * be done on this core.
	 */
	ASSERT_TRUE(hftest_cpu_start(
		hftest_get_cpu_id(receiver_vcpu1_args.vcpu_id),
		hftest_get_secondary_ec_stack(receiver_vcpu1_args.vcpu_id),
		cpu_entry_receive_ipi_waiting,
		(uintptr_t)&receiver_vcpu1_args));

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&receiver_vcpu1_args.work_done);

	/* Resumes service on target vCPU to handle IPI. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * Target SP is waiting state when interrupt fires, so the SPMC sends SRI to
 * the NWd for the scheduler to explicitly provide CPU cycles.
 * The sequence is due to 'sri-interrupts-policy' field in the respective
 * manifest.
 *
 * The test uses ESPI interrupts, and a platform specific ABI to trigger
 * interrupts in the ESPI range:
 * - Service1 is configured in a way it can use the aforementioned platform
 *   ABI.
 * - Service2 is assigned with a dummy device, which is configured with
 *   interrupt in ESPI range.
 * - Reused the hf_ipi_state_* abstractions given they fulfill the needful
 *   for this test.
 *
 * Test sequence:
 * - PVM creates an interrupt state structure, which can be used to synchronise
 *   between endpoints on the state of the interrupt. It also configures itself
 *   to use the GIC and handle the SRI interrupt.
 * - PMV bootstraps Service1 to `send_espi_interrupt` and Service2 to
 *   `receive_interrupt_waiting_vcpu_sri_triggered`.
 * - PVM shares the state with both service1 and service2.
 * - Service2 is resumed to be ready to handle the ESPI. It also calls
 *   FFA_MSG_WAIT to be set in waiting state when interrupt is triggered.
 * - Service1 is resumed to put itself in a state from which it can
 *   receive the ESPI ID to trigger.
 * - Send the ESPI ID to Service1, and resume it.
 * - Service1 returns without triggering ESPI. This is so the SRI due indirect
 *   messaging is handled first.
 * - Service1 is resumed such that it can trigger ESPI. The SPMC should send
 *   SRI to the NWd.
 * - Service1 terminates.
 * - PVM resumes, waiting for the SRI.
 * - PVM invokes FFA_NOTIFICATION_INFO_GET, attest the return.
 * - PVM resumes Service2 to handle the EPSI.
 * - Service2 resumes, execution should reach the IRQ handler.
 * - Service2 attests interrupt has been handled and terminates.
 */
TEST_PRECONDITION(secure_interrupts, sri_triggered_due_to_secure_interrupt,
		  service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	uint32_t sri_id;
	uint32_t expected_list_count = 1;
	uint32_t expected_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint16_t expected_ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	ffa_id_t memory_receivers[] = {service1_info->vm_id,
				       service2_info->vm_id};
	uint32_t receivers_ipi_state_indexes[] = {0};
	struct ffa_value ret;
	/*
	 * Interrupt ID assigned to device `espi_test_node`, in manifest
	 * of service2.
	 */
	const uint32_t espi_id = 5000;

	/* Get ready to handle SRI.  */
	gicv3_system_setup();
	sri_id = enable_sri();

	/* Init vCPU which will handle interrupt. */
	SERVICE_SELECT(service2_info->vm_id,
		       "receive_interrupt_waiting_vcpu_sri_triggered", mb.send);

	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Init vCPU which will send interrupt. */
	SERVICE_SELECT(service1_info->vm_id, "send_espi_interrupt", mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share the interrupt state with both services. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	/* Resume Service2 so it can prepare itself to handle the ESPI. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Resume Service1 to attest Service2 is ready, and prepare to
	 * send ESPI.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send interrupt ID to service1. */
	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, (void *)&espi_id, sizeof(espi_id),
				    0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* FFA_RUN service1 to retrieve the interrupt state. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	last_interrupt_id = 0;

	/*
	 * Rerunning now such that the SRI due to indirect messaging
	 * is now resolved. At this point the SRI can only be due to
	 * eSPI given no messages are being exchanged.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Wait for SRI. */
	while (last_interrupt_id != sri_id) {
		interrupt_wait();
	}

	/*
	 * Check that service2, vCPU 0 are returned by
	 * FFA_NOTIFICATION_INFO_GET.
	 */
	expected_lists_sizes[0] = 1;
	expected_ids[0] = service2_info->vm_id;
	expected_ids[1] = 0;

	ffa_notification_info_get_and_check(expected_list_count,
					    expected_lists_sizes, expected_ids);

	EXPECT_FALSE(hftest_ipi_state_is(HANDLED));

	/* Resumes service2 in target vCPU 0 to handle the ESPI. */
	EXPECT_EQ(ffa_run(service2_info->vm_id, 0).func, FFA_YIELD_32);
}

/**
 * Target SP goes into waiting state whith interrupt pending, so the SPMC sends
 * SRI to the NWd for the scheduler to explicitly provide CPU cycles at a later
 * instance. The sequence is due to 'sri-interrupts-policy' field in the
 * respective manifest.
 *
 * The test uses ESPI interrupts, and a platform specific ABI to trigger
 * interrupts in the ESPI range:
 * - Service1 is configured in a way it can use the aforementioned platform
 *   ABI.
 * - Service3 is assigned with a dummy device, which is configured with
 * interrupt in ESPI range.
 * - Reused the hf_ipi_state_* abstractions given they fulfill the needful
 *   for this test.
 *
 * Test sequence:
 * - PVM creates an interrupt state structure, which can be used to synchronise
 *   between endpoints on the state of the interrupt. It also configures itself
 *   to use the GIC and handle the SRI interrupt.
 * - PMV bootstraps Service1 to `send_espi_interrupt` and Service3 to
 *   `receive_interrupt_sri_triggered_into_waiting`.
 * - PVM shares the state with both service1 and service3.
 * - Service3 is resumed, so it is ready to handle the ESPI. It masks
 *   interrupts such when it is next resumed, execution doesn't reach IRQ
 *   handler.
 * - Service1 is resumed to put itself in a state from which it can
 *   receive the ESPI ID to trigger.
 * - Send the ESPI ID to Service1, and resume it.
 * - Service1 returns without triggering ESPI. This is so the SRI due
 *   indirect messaging is handled first.
 * - PVM resumes, handles SRI from indirect messaging and resumes Service1 to
 *   trigger the ESPI.
 * - Service1 resumes, triggers ESPI and terminates.
 * - Service3 is resumed with interrupts pending. It calls FFA_MSG_WAIT.
 *   This should trigger the SRI for the PVM.
 * - PVM resumes, attesting it handled the SRI. It calls
 * FFA_NOTIFICATION_INFO_GET and resumes Service3.
 * - Service3 resumes, unmaks interrupts. Execution should reach the interrupt
 *   handler. Attest the interrupt state is "HANDLED" and terminates.
 */
TEST_PRECONDITION(secure_interrupts,
		  sri_triggered_due_to_secure_interrupt_transition_waiting,
		  service1_is_mp_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	uint32_t sri_id;
	uint32_t expected_list_count = 1;
	uint32_t expected_lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint16_t expected_ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	ffa_id_t memory_receivers[] = {service1_info->vm_id,
				       service3_info->vm_id};
	uint32_t receivers_ipi_state_indexes[] = {0};
	struct ffa_value ret;
	/*
	 * Interrupt ID assigned to device `espi_test_node`, in manifest
	 * of service2.
	 */
	const uint32_t espi_id = 5001;

	/* Get ready to handle SRI.  */
	gicv3_system_setup();
	sri_id = enable_sri();

	/* Init vCPU which will send interrupt. */
	SERVICE_SELECT(service1_info->vm_id, "send_espi_interrupt", mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Init vCPU which will handle interrupt. */
	SERVICE_SELECT(service3_info->vm_id,
		       "receive_interrupt_sri_triggered_into_waiting", mb.send);

	ret = ffa_run(service3_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Share the interrupt state with both. */
	hftest_ipi_state_share_page_and_init(
		(uint64_t)interrupt_state_page, memory_receivers,
		receivers_ipi_state_indexes, ARRAY_SIZE(memory_receivers),
		mb.send, 0);

	/* FFA_RUN service3 ready for eSPI triggering. */
	ret = ffa_run(service3_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* FFA_RUN service1 to retrieve the interrupt state. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send interrupt ID to sender service. */
	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, (void *)&espi_id, sizeof(espi_id),
				    0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* FFA_RUN service1 to retrieve the interrupt state. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* FFA_RUN service1 to send ESPI. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Expecting the SRI to trigger now. */
	last_interrupt_id = 0;

	dlog_info("Resuming %x it should trigger SRI.", service3_info->vm_id);

	ret = ffa_run(service3_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	while (last_interrupt_id != sri_id) {
		interrupt_wait();
	}

	/* Check the target vCPU 0 is returned by FFA_NOTIFICATION_INFO_GET. */
	expected_lists_sizes[0] = 1;
	expected_ids[0] = service3_info->vm_id;
	expected_ids[1] = 0;

	ffa_notification_info_get_and_check(expected_list_count,
					    expected_lists_sizes, expected_ids);

	/* Resumes service3 in target vCPU 0 to handle IPI. */
	EXPECT_EQ(ffa_run(service3_info->vm_id, 0).func, FFA_YIELD_32);
}
