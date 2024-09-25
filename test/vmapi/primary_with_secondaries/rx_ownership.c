/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/semaphore.h"
#include "test/vmapi/ffa.h"

/**
 * Structure defined for usage in tests with multiple cores.
 * Used to pass arguments from primary to secondary core.
 */
struct secondary_cpu_entry_args {
	ffa_id_t receiver_id;
	ffa_vcpu_index_t vcpu_id;
	ffa_vcpu_count_t receiver_vcpu_count;
	struct mailbox_buffers mb;
	struct semaphore sync;
};

/**
 * Test to verify that when an SP calls FFA_MSG_WAIT, it relinquishes the
 * ownership of its RX buffer back to the SPMC. Test sequence is as follows:
 * 	1. PVM runs SP via FFA_RUN.
 * 	2. SP calls FFA_PARTITION_INFO_GET to gain ownership of its RX buffer
 * from the SPMC.
 * 	3. SP calls FFA_MSG_WAIT, relinquishing RX buffer to SPMC and control
 * back to PVM.
 * 	4. PVM sends SP an indirect message to fill the RX buffer and runs via
 * FFA_RUN.
 * 	5. SP  successfully receives indirect message, verifying the message
 * sent from the PVM.
 */
TEST_PRECONDITION(rx_ownership, ffa_msg_wait_buffer_full, service1_is_not_vm)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;
	uint64_t msg = 0x123;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "test_ffa_msg_wait_release_buffer",
		       mb.send);

	/* Run service to call FFA_PARTITION_INFO_GET, then FFA_MSG_WAIT. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Run service again after FFA_MSG_WAIT (which should have released
	 * the buffer). Sending an indirect message should succeed since buffer
	 * was released back to SPMC.
	 */
	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, &msg, sizeof(msg), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

/**
 * Test to verify that when an SP calls FFA_MSG_WAIT with the
 * FFA_MSG_WAIT_FLAG_RETAIN_RX flag it does not relinquish ownership of its RX
 * buffer back to the SPMC. Test sequence is as follows:
 * 	1. PVM runs SP via FFA_RUN.
 * 	2. SP calls FFA_PARTITION_INFO_GET to gain ownership of its RX buffer
 * from the SPMC.
 * 	3. SP calls FFA_MSG_WAIT with FFA_MSG_WAIT_FLAG_RETAIN_RX flag
 * returning control back to PVM but keeping ownership of the RX buffer.
 * 	4. PVM runs SP via FFA_RUN.
 * 	5. SP calls FFA_PARTITION_INFO_GET and checks that if fails because the
 * 	SPMC does not have ownership of the buffer and cannot fill it.
 */
TEST_PRECONDITION(rx_ownership, ffa_msg_wait_retain_buffer, service1_is_not_vm)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;

	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "test_ffa_msg_wait_retain_buffer",
		       mb.send);

	/*
	 * Run service to call FFA_PARTITION_INFO_GET, then FFA_MSG_WAIT with
	 * the flag to retain the RX buffer set.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Run service to attempt to call FFA_PARTITION_INFO_GET again and check
	 * that it fails since FFA_MSG_WAIT did not release RX buffer to the
	 * SPMC.
	 */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}

static void cpu_entry_mp(uintptr_t arg)
{
	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;
	ffa_vcpu_index_t service_vcpu_id;
	struct ffa_value ret;
	uint64_t msg = 0x123;

	ASSERT_TRUE(args != NULL);

	HFTEST_LOG("Within secondary core... %u", args->vcpu_id);
	service_vcpu_id = (args->receiver_vcpu_count > 1) ? args->vcpu_id : 0;

	SERVICE_SELECT_MP(args->receiver_id, "call_ffa_msg_wait_retain_rx",
			  args->mb.send, service_vcpu_id);

	ret = send_indirect_message(hf_vm_get_id(), args->receiver_id,
				    args->mb.send, &msg, sizeof(msg), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(args->receiver_id, service_vcpu_id);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Signal to primary core that test is complete.*/
	HFTEST_LOG("Done with secondary core...");
	semaphore_signal(&args->sync);
}

/**
 * Test to show that one vCPU calling FFA_MSG_WAIT with retain buffer flag will
 * not prevent another vCPU from reading the RX buffer.
 *
 *	1. SPMC sends indirect message intended to be read by SP vCPU 1 (msg =
 * 0x123). RX buffer ownership is transferred from Producer (SPMC) to consumer
 * (SP).
 *	2. SP vCPU 0 calls FFA_MSG_WAIT with retain RX buffer flag set to 1 so
 * the RX buffer ownership still belongs to the SP.
 *	3. SP vCPU 1 reads buffer after FFA_MSG_WAIT call.
 */
TEST_PRECONDITION(rx_ownership, ffa_msg_wait_race_success, service1_is_mp_sp)
{
	struct mailbox_buffers mb_mp = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb_mp.recv);
	const ffa_vcpu_index_t vcpu_id = 1;
	struct secondary_cpu_entry_args args = {
		.receiver_id = service1_info->vm_id,
		.receiver_vcpu_count = service1_info->vcpu_count,
		.vcpu_id = vcpu_id,
		.mb = mb_mp,
	};
	struct ffa_value ret;

	SERVICE_SELECT_MP(service1_info->vm_id, "read_rx_buffer", mb_mp.send,
			  0);

	/*
	 * Initialize semaphore for synchronization purposes between primary and
	 * secondary core.
	 */
	semaphore_init(&args.sync);

	/* Start service on SP vCPU 1 */
	HFTEST_LOG("Starting secondary core...");

	ASSERT_TRUE(hftest_cpu_start(hftest_get_cpu_id(vcpu_id),
				     hftest_get_secondary_ec_stack(vcpu_id),
				     cpu_entry_mp, (uintptr_t)&args));

	/* Wait for secondary core to return before finishing the test. */
	semaphore_wait(&args.sync);
	HFTEST_LOG("Returned from secondary core");

	/* vCPU 0 on service1 reads RX buffer. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	HFTEST_LOG("Finished the test...");
}

/**
 * Test to verify that when an SP calls FFA_MSG_WAIT with the
 * FFA_MSG_WAIT_FLAG_RETAIN_RX flag it does not relinquish ownership of its RX
 * buffer back to the SPMC. Test sequence is as follows:
 * 	1. PVM runs SP via FFA_RUN.
 * 	2. SP calls FFA_PARTITION_INFO_GET to gain ownership of its RX buffer
 * from the SPMC.
 * 	3. SP calls FFA_MSG_WAIT with FFA_MSG_WAIT_FLAG_RETAIN_RX flag
 * returning control back to PVM but keeping ownership of the RX buffer.
 * 	4. PVM sends SP an indirect message to fill the RX buffer which will
 * fails as SPMC does not have ownership of the buffer and cannot fill it.
 */
TEST_PRECONDITION(rx_ownership, ffa_msg_wait_retain_buffer_indirect_msg_fail,
		  service1_is_not_vm)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;
	uint64_t msg = 0x123;
	struct ffa_partition_info *service1_info = service1(mb.recv);

	SERVICE_SELECT(service1_info->vm_id, "test_ffa_msg_wait_retain_buffer",
		       mb.send);

	/* Run service to call FFA_PARTITION_INFO_GET, then FFA_MSG_WAIT. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Run service again after FFA_MSG_WAIT (which should have retained
	 * the buffer). Sending an indirect message should fail since buffer
	 * was not released back to SPMC.
	 */
	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, &msg, sizeof(msg), 0);
	ASSERT_EQ(ret.func, FFA_ERROR_32);
}

/**
 * This test ensures that when an SP has a pending message in its RX buffer,
 * a call to FFA_MSG_WAIT will not release the RX buffer to the producer, even
 * if the FFA_MSG_WAIT_FLAG_RETAIN_RX flag is not used. The test sequence is as
 * follows:
 *	1. Send indirect message to SP1 to fill its RX buffer.
 *	2. Run SP1. SP1 calls FFA_MSG_WAIT without flag, and enters the WAITING
 * state, but does not release the RX buffer due to pending message.
 *	3. Run SP2 to send indirect message to SP1 and attest that the send
 * fails.
 *	4. Return to SP1 and attest the message is same as originally sent by
 * the PVM.
 */
TEST(rx_ownership, ffa_msg_wait_with_pending_message)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value ret;
	uint64_t msg = 0x123;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	SERVICE_SELECT(service1_info->vm_id,
		       "ffa_msg_wait_pending_indirect_message", mb.send);

	/* Service2 to send indirect message to Service1. */
	SERVICE_SELECT(service2_info->vm_id, "send_indirect_msg_to_sp_fail",
		       mb.send);

	/* Send indirect message to Service1. */
	ret = send_indirect_message(hf_vm_get_id(), service1_info->vm_id,
				    mb.send, &msg, sizeof(msg), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	/* Run Service1 to call FFA_MSG_WAIT. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Send Service2 ID of Service1. */
	ret = send_indirect_message(hf_vm_get_id(), service2_info->vm_id,
				    mb.send, &service1_info->vm_id,
				    sizeof(service1_info->vm_id), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	/* Run Service2. */
	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Run Service1 to read original message. */
	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}
