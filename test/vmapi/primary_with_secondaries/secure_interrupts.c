/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"

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
