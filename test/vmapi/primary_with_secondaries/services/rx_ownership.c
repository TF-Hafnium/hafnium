/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/semaphore.h"
#include "test/vmapi/ffa.h"

/* Used to coordinate between multiple vCPUs in multicore test. */
static struct semaphore ffa_msg_wait_called;

TEST_SERVICE(test_ffa_msg_wait_release_buffer)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;
	void *recv_buf = SERVICE_RECV_BUFFER();
	uint64_t msg;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	dlog_verbose("FFA_PARTITION_INFO_GET put the RX buffer FULL.");

	/*
	 * Subsequent call to FFA_PARTITION_INFO_GET should fail because buffer
	 * is busy.
	 */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	dlog_verbose("FFA_PARTITION_INFO_GET attested the RX buffer is FULL.");

	/* FFA_MSG_WAIT should release buffer. */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Read RX buffer and verify expected message payload. */
	receive_indirect_message((void *)&msg, sizeof(msg), recv_buf, NULL);
	EXPECT_EQ(msg, 0x123);

	dlog_verbose(
		"Attested that RX buffer was available to receive indirect "
		"message.");

	ffa_yield();
}

TEST_SERVICE(test_ffa_msg_wait_retain_buffer)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	dlog_verbose("FFA_PARTITION_INFO_GET put the RX buffer FULL.");

	/*
	 * Subsequent call to FFA_PARTITION_INFO_GET should fail because buffer
	 * is busy.
	 */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	dlog_verbose("FFA_PARTITION_INFO_GET attested the RX buffer is FULL.");

	/* FFA_MSG_WAIT should retain buffer. */
	ret = ffa_msg_wait_with_flags(FFA_MSG_WAIT_FLAG_RETAIN_RX);
	EXPECT_EQ(ret.func, FFA_RUN_32);
	dlog_verbose("FFA_MSG_WAIT returned");

	/*
	 * Additional call to ffa_partition_info_get should fail since buffer
	 * was retained.
	 */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);
	dlog_verbose(
		"FFA_PARTITION_INFO_GET attested the RX buffer is FULL after "
		"retention.");

	ffa_yield();
}

TEST_SERVICE(read_rx_buffer)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	uint64_t msg;

	/* Wait until FFA_MSG_WAIT has been called on other VCPU. */
	semaphore_wait(&ffa_msg_wait_called);

	/* Read RX buffer and verify expected message payload. */
	receive_indirect_message((void *)&msg, sizeof(msg), recv_buf, NULL);
	EXPECT_EQ(msg, 0x123);
	ffa_yield();
}

TEST_SERVICE(call_ffa_msg_wait_retain_rx)
{
	struct ffa_value ret;
	HFTEST_LOG("Call FFA_MSG_WAIT");

	/* FFA_MSG_WAIT should retain buffer */
	semaphore_init(&ffa_msg_wait_called);
	semaphore_signal(&ffa_msg_wait_called);
	ret = ffa_msg_wait_with_flags(FFA_MSG_WAIT_FLAG_RETAIN_RX);
	EXPECT_EQ(ret.func, FFA_RUN_32);

	ffa_yield();
}

TEST_SERVICE(send_indirect_msg_to_sp_fail)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	ffa_id_t target_id;
	uint64_t msg = 0x4321;
	struct ffa_value ret;

	/* Receive ID of service to send message to. */
	receive_indirect_message((void *)&target_id, sizeof(target_id),
				 recv_buf, NULL);

	HFTEST_LOG("Attempting to send indirect message %lx to %x", msg,
		   target_id);
	ret = send_indirect_message(hf_vm_get_id(), target_id, send_buf, &msg,
				    sizeof(msg), 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);
	ffa_yield();
}

TEST_SERVICE(ffa_msg_wait_pending_indirect_message)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value ret;
	uint64_t msg;

	/*
	 * FFA_MSG_WAIT will attempt to release buffer.
	 * RUNNING -> WAITING state transition should succeed, but
	 * buffer release should fail due to pending indirect message
	 * sent by PVM.
	 */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Read RX buffer and verify expected message payload from PVM. */
	receive_indirect_message((void *)&msg, sizeof(msg), recv_buf, NULL);
	EXPECT_EQ(msg, 0x123);

	dlog_verbose(
		"Attested that RX buffer was available to receive indirect "
		"message.");

	ffa_yield();
}
