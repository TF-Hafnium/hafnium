/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/semaphore.h"

/**
 * Structure defined for usage in tests with multiple cores.
 * Used to pass arguments from primary to secondary core.
 */
struct ipi_cpu_entry_args {
	ffa_id_t service_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_vcpu_index_t vcpu_id;
	ffa_vcpu_index_t target_vcpu_id;
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
	const uint32_t echo_payload;
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

	receive_indirect_message((void *)&echo_payload, sizeof(echo_payload),
				 mb.recv, &echo_sender);

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

	ASSERT_TRUE(args != NULL);
	ASSERT_TRUE(args->vcpu_count > 1);

	HFTEST_LOG("%s: Within secondary core... %u", __func__, args->vcpu_id);

	SERVICE_SELECT_MP(args->service_id, "send_ipi", args->mb.send,
			  args->vcpu_id);

	/* Run service. */
	ret = ffa_run(args->service_id, args->vcpu_id);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send it the target vCPU ID. */
	ret = send_indirect_message(own_id, args->service_id, args->mb.send,
				    &args->target_vcpu_id,
				    sizeof(args->target_vcpu_id), 0);

	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_run(args->service_id, args->vcpu_id).func, FFA_YIELD_32);

	HFTEST_LOG("%s cpu done...", __func__);

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
		.target_vcpu_id = 0,
		.mb = mb};

	/* Initialize semaphores to sync primary and secondary cores. */
	semaphore_init(&vcpu1_args.work_done);

	SERVICE_SELECT(service1_info->vm_id, "receive_ipi_running", mb.send);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

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
