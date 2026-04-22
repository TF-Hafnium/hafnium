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
#include "test/vmapi/ffa.h"

alignas(PAGE_SIZE) static uint8_t shared_page[PAGE_SIZE];

#define FFA_VERSION_NULL make_ffa_version(0, 0)

/**
 * Service for indirect message error checking.
 * The VM unmap its RX/TX and waits for a message.
 */
TEST_SERVICE(ffa_indirect_msg_error)
{
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);

	ffa_msg_wait();
}

/**
 * Service waits for a direct message request but primary VM
 * calls ffa_run instead. Verify the service does not run.
 */
TEST_SERVICE(ffa_direct_msg_run)
{
	struct ffa_value res = ffa_msg_wait();

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 1);

	res = ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 2, 0,
				       0, 0, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(res.arg3, 3);

	ffa_msg_send_direct_resp(ffa_receiver(res), ffa_sender(res), 4, 0, 0, 0,
				 0);
}

/**
 * Service to test an SP cannot negotiate its version whilst its RX/TX buffers
 * are mapped.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_rxtx)
{
	/*
	 * R0238: an incompatible request returns the highest supported
	 * version even while the RX/TX mappings keep the framework in use.
	 */
	EXPECT_EQ(
		ffa_version(FFA_VERSION_COMPILED + 1, VERSION_QUERY_NEGOTIATE),
		FFA_VERSION_COMPILED);

	/*
	 * Expect the Null version because the RX/TX buffers are still mapped to
	 * coordinate the service select.
	 */
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	/*
	 * Check that if the buffers are unmapped the version can be
	 * renegotiated.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/**
 * Service to test an SP cannot negotiate its version whilst it is actively
 * sharing memory.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_mem_share)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)shared_page, .page_count = 1},
	};
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t msg_size;

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  SERVICE_SEND_BUFFER(), HF_MAILBOX_SIZE,
			  hf_vm_get_id(), service2_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_share(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	/*
	 * Unmap RX/TX Buffer so mem share is the only reason the FFA_VERSION
	 * should return the Null version.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	/* After reclaiming the memory the FFA_VERSION should now succeed. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/**
 * Service to test an SP cannot negotiate its version whilst it has lent
 * memory that has not been reclaimed.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_mem_lend)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)shared_page, .page_count = 1},
	};
	struct ffa_partition_info *service2_info = service2(recv_buf);
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t msg_size;

	EXPECT_EQ(ffa_memory_region_init_single_receiver(
			  SERVICE_SEND_BUFFER(), HF_MAILBOX_SIZE,
			  hf_vm_get_id(), service2_info->vm_id, constituents,
			  ARRAY_SIZE(constituents), 0, 0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NOT_SPECIFIED_MEM,
			  FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, NULL, NULL, &msg_size),
		  0);

	ret = ffa_mem_lend(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);

	/*
	 * Unmap RX/TX buffers so the lend is the only reason FFA_VERSION
	 * should return the Null version.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	/* Reclaiming the memory permits version negotiation again. */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/**
 * Service to test an SP cannot negotiate its version whilst it is actively
 * borrowing memory.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_mem_borrow)
{
	ffa_memory_handle_t handle;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();

	retrieve_memory_from_message(recv_buf, send_buf, &handle, NULL,
				     HF_MAILBOX_SIZE);

	/*
	 * Unmap RX/TX Buffer so memory borrow is the only reason the
	 * FFA_VERSION should return the Null version.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	/* Remap the buffers for the relinquish request. */
	EXPECT_EQ(ffa_rxtx_map((hf_ipaddr_t)SERVICE_SEND_BUFFER(),
			       (hf_ipaddr_t)SERVICE_RECV_BUFFER())
			  .func,
		  FFA_SUCCESS_32);

	/* Give the memory back and notify the sender. */
	ffa_mem_relinquish_init(send_buf, handle, 0, hf_vm_get_id());
	EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);

	/*
	 * Unmap RX/TX Buffer and the FFA_VERSION should now succeed.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/**
 * Service to test a donation does not make the framework in use. D0234 in the
 * DEN0077A FF-A v1.3 ALP5 specification only considers outstanding lend and
 * share transactions.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_not_in_use_mem_donate)
{
	struct mailbox_buffers mb = get_service_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)shared_page, .page_count = 1},
	};

	send_memory_and_retrieve_request(
		FFA_MEM_DONATE_32, &mb, hf_vm_get_id(), service2_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_NOT_SPECIFIED, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/* Remove RX/TX mappings so the donation is the only relevant state. */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/**
 * Service to test an SP cannot negotiate its version whilst it has
 * notifications bound.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_notifications_bound)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_partition_info *service2_info = service2(recv_buf);
	ffa_notifications_bitmap_t bitmap = FFA_NOTIFICATION_MASK(1);

	EXPECT_EQ(ffa_notification_bind(service2_info->vm_id, hf_vm_get_id(), 0,
					bitmap)
			  .func,
		  FFA_SUCCESS_32);

	/*
	 * Unmap RX/TX Buffer so the existing notification binding is the only
	 * reason the FFA_VERSION should return the Null version.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	EXPECT_EQ(ffa_notification_unbind(service2_info->vm_id, hf_vm_get_id(),
					  bitmap)
			  .func,
		  FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/**
 * Service to test an SP cannot negotiate its version whilst it has
 * notifications pending.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_notifications_pending)
{
	struct ffa_value ret;
	ffa_notifications_bitmap_t fwk_notif;

	/* Allow the primary to queue an indirect message first. */
	ffa_yield();

	/*
	 * Unmap RX/TX Buffer so pending notifications are the only reason the
	 * FFA_VERSION should return the Null version.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	ret = ffa_notification_get(hf_vm_get_id(), 0,
				   FFA_NOTIFICATION_FLAG_BITMAP_SPM |
					   FFA_NOTIFICATION_FLAG_BITMAP_HYP);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	fwk_notif = ffa_notification_get_from_framework(ret);
	EXPECT_TRUE(is_ffa_hyp_buffer_full_notification(fwk_notif));

	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}

/*
 * Service run on vCPU 0 to create a blocked FF-A call while another vCPU
 * checks the framework-in-use condition.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_blocked_call_blocker)
{
	/*
	 * Remove RX/TX ownership so only the blocked FF-A call gates VERSION.
	 */
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);

	/*
	 * Yield creates the blocked outstanding FF-A call. The caller resumes
	 * another vCPU to check FFA_VERSION.
	 */
	ffa_yield();

	/*
	 * On resumption, enter WAITING so this vCPU no longer has an
	 * outstanding invocation when vCPU 1 retries negotiation.
	 */
	ffa_msg_wait();
}

/*
 * Service run on vCPU 1 to observe FFA_VERSION returning the Null version
 * while vCPU 0 has a blocked FF-A call outstanding, then succeeding once
 * vCPU 0 enters WAITING.
 */
TEST_SERVICE(ffa_version_negotiate_fwk_in_use_blocked_call_observer)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_NULL);

	ffa_yield();

	/* The primary resumes this vCPU only after vCPU 0 enters WAITING. */
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED, VERSION_QUERY_NEGOTIATE),
		  FFA_VERSION_COMPILED);

	ffa_yield();
}
