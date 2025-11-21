/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/arch/vm/delay.h"
#include "hf/arch/vm/power_mgmt.h"
#include "hf/arch/vmid_base.h"

#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/hftest_impl.h"
#include "test/semaphore.h"
#include "test/vmapi/ffa.h"

const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
			0x88889999};

alignas(PAGE_SIZE) static uint8_t pages[PAGE_SIZE];

/**
 * Send a direct request message to target SP and expect it to abort using
 * FFA_ABORT ABI. Perform the partition discovery via FFA_PARTITION_INFO_GET
 * interface both before and after the target SP is aborted. Any attempt to
 * communicate with target SP shall return appropriate error status.
 */
ffa_vm_count_t base_helper_sp_abort_dir_req_from_vm(
	struct ffa_partition_info *target_sp_info, struct mailbox_buffers mb,
	enum ffa_error error_code)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_uuid uuid;
	ffa_vm_count_t vm_count;
	struct ffa_value ret;
	uint64_t data = 0x123;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	vm_count = ffa_partition_info_get_count(ret);

	/* 5 FF-A partitions with one partition having with 2 UUIDs. */
	EXPECT_EQ(vm_count, 6);

	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_dir_req", mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_ABORTED);

	/*
	 * Attempt to communicate with target SP. SPMC shall return error
	 * status.
	 */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, error_code);

	/*
	 * Attempt to send an indirect message to target SP. SPMC shall return
	 * error status.
	 */
	ret = send_indirect_message(own_id, target_sp_info->vm_id, mb.send,
				    &data, sizeof(data), 0);

	EXPECT_FFA_ERROR(res, error_code);

	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	vm_count = ffa_partition_info_get_count(ret);

	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	return vm_count;
}

/**
 * Upon aborting, the target SP shall be stopped and its execution context will
 * be put in STOPPED state. Any attempt to communicate with the SP shall return
 * FFA_BUSY error status through FFA_ERROR interface.
 */
TEST(sp_lifecycle, stop_sp_upon_abort)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service1(mb.recv);
	ffa_vm_count_t vm_count;

	vm_count = base_helper_sp_abort_dir_req_from_vm(target_sp_info, mb,
							FFA_BUSY);

	/* Service3 SP is still discoverable after aborting. */
	EXPECT_EQ(vm_count, 6);
}

/**
 * Upon aborting, the target SP shall be destroyed and its execution context
 * will be put in NULL state. Any attempt to communicate with the SP shall
 * return FFA_INVALID_PARAMETERS error status through FFA_ERROR interface.
 */
TEST(sp_lifecycle, destroy_sp_upon_abort)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service3(mb.recv);
	ffa_vm_count_t vm_count;

	vm_count = base_helper_sp_abort_dir_req_from_vm(target_sp_info, mb,
							FFA_INVALID_PARAMETERS);

	/* Service3 SP is no more discoverable after aborting. */
	EXPECT_EQ(vm_count, 5);
}

/**
 * Send an indirect message to SP and allocate CPU cycles through FFA_RUN.
 * Expect the SP to abort using FFA_ABORT. Any attempt to communicate with the
 * SP shall return error status.
 */
TEST_PRECONDITION(sp_lifecycle, sp_abort_indirect_message, service1_is_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *target_sp_info = service1(mb.recv);
	const uint32_t payload = 0xAABBCC;
	ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_indirect_message",
		       mb.send);
	res = ffa_run(target_sp_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	res = send_indirect_message(own_id, target_sp_info->vm_id, mb.send,
				    &payload, sizeof(payload), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);

	/* Expect the target SP to abort while handling indirect message. */
	res = ffa_run(target_sp_info->vm_id, 0);
	EXPECT_FFA_ERROR(res, FFA_ABORTED);

	/*
	 * Attempt to communicate with target SP. SPMC shall return BUSY status.
	 */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_BUSY);
}

/**
 * Send a direct request message to S-EL0 target SP and expect it to abort upon
 * encountering a fatal error due to a synchronous exception. Any attempt to
 * communicate with the target SP shall return error status.
 */
TEST(sp_lifecycle, sel0_sp_abort_fatal_error)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *target_sp_info = service1(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(target_sp_info->vm_id, "sp_fatal_error_sync_exception",
		       mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_ABORTED);

	/* Attempt to communicate with target SP. */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	/*
	 * Since Service1 SP didn't specify any abort action explcitly, SPMC
	 * put the partition in STOPPED state and return BUSY error status.
	 */
	EXPECT_FFA_ERROR(res, FFA_BUSY);
}

/**
 * Same test as above except that the target endpoint is S-EL1 SP.
 */
TEST(sp_lifecycle, sel1_sp_abort_fatal_error)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;
	struct ffa_partition_info *target_sp_info = service3(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(target_sp_info->vm_id, "sp_fatal_error_sync_exception",
		       mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_ABORTED);

	/* Attempt to communicate with target SP. */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	/*
	 * SPMC shall return INVALID PARAMETERS error status as the target SP
	 * is going to be destroyed (since the abort action specified in the
	 * manifest is DESTROY).
	 */
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * This test aims to create a scenario where the target endpoint aborts
 * voluntarily while handling a direct request from an initiator endpoint. SPMC
 * shall return suitable error return status to initiator. To be robust, this
 * test also configures the initiator endpoint to perform a handshake with a
 * companion endpoint to ensure SPMC preserves the state of various endpoints in
 * a system even after abort handling.
 *
 * Roles played by various endpoints to facilitate above test scenario:
 *  Service1 SP - Target endpoint
 *  Service2 SP - Initiator endpoint
 *  Service3 SP - Companion endpoint
 */
TEST_PRECONDITION(sp_lifecycle, sp_abort_dir_req_from_sp,
		  service1_and_service2_are_secure)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service1(mb.recv);
	struct ffa_partition_info *initiator_info = service2(mb.recv);
	struct ffa_partition_info *companion_info = service3(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	/*
	 * Run target endpoint for it to wait for a request from Initiator
	 * endpoint and then voluntarily abort its execution using FFA_ABORT.
	 */
	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_dir_req", mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	/*
	 * Run companion endpoint for it to wait for a request from initiator
	 * endpoint.
	 */
	SERVICE_SELECT(companion_info->vm_id, "ffa_direct_message_resp_echo",
		       mb.send);
	ffa_run(companion_info->vm_id, 0);

	/*
	 * Initiator endpoint sends direct request to target endpoint and
	 * expects it to be aborted.
	 */
	SERVICE_SELECT(initiator_info->vm_id,
		       "sp_to_sp_dir_req_abort_start_another_dir_req", mb.send);

	/*
	 * Send to Initiator endpoint, the vm id of the target endpoint for its
	 * message.
	 */
	res = send_indirect_message(own_id, initiator_info->vm_id, mb.send,
				    &target_sp_info->vm_id,
				    sizeof(target_sp_info->vm_id), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);
	ffa_run(initiator_info->vm_id, 0);

	/*
	 * Attempt to communicate with target SP. SPMC shall return BUSY status.
	 */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_BUSY);

	/* Send to initiator_info the vm id of the companion for its message. */
	res = send_indirect_message(own_id, initiator_info->vm_id, mb.send,
				    &companion_info->vm_id,
				    sizeof(companion_info->vm_id), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);
	ffa_run(initiator_info->vm_id, 0);
}

/**
 * This test aims to create a scenario where the target endpoint aborts
 * voluntarily while handling a secure virtual interrupt in SPMC schedule mode.
 */
TEST_PRECONDITION(sp_lifecycle, sp_preempts_vm_aborts_spmc_mode,
		  service1_is_secure)
{
	struct ffa_value res;
	const uint32_t delay = 20;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service1(mb.recv);

	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_sec_int_handling",
		       mb.send);

	/*
	 * Send an indirect message to convey the Secure Watchdog timer delay
	 * which serves as the source of the secure interrupt.
	 */
	res = send_indirect_message(own_id, target_sp_info->vm_id, mb.send,
				    &delay, sizeof(delay), 0);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Schedule message receiver through FFA_RUN interface. */
	res = ffa_run(target_sp_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	/* Wait for the interrupt to trigger. */
	waitms(delay + 50);

	/*
	 * Attempt to communicate with target SP. SPMC shall return BUSY status.
	 */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_BUSY);
}

/**
 * This test aims to create a scenario where a secure physical interrupt
 * preempts a companion endpoint followed by the target endpoint aborting
 * while handling the corresponding secure virtual interrupt.
 */
TEST_PRECONDITION(sp_lifecycle, sp_preempts_sp_aborts_spmc_mode,
		  service1_is_secure)
{
	struct ffa_value res;
	const uint32_t delay = 20;
	const uint32_t wait = delay + 50;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service1(mb.recv);
	struct ffa_partition_info *companion_info = service2(mb.recv);

	SERVICE_SELECT(companion_info->vm_id, "sp_active_wait", mb.send);

	/* Send an indirect message to convey the wait duration. */
	res = send_indirect_message(own_id, companion_info->vm_id, mb.send,
				    &wait, sizeof(wait), 0);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Schedule message receiver through FFA_RUN interface. */
	res = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_sec_int_handling",
		       mb.send);

	/*
	 * Send an indirect message to convey the Secure Watchdog timer delay
	 * which serves as the source of the secure interrupt.
	 */
	res = send_indirect_message(own_id, target_sp_info->vm_id, mb.send,
				    &delay, sizeof(delay), 0);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Schedule message receiver through FFA_RUN interface. */
	res = ffa_run(target_sp_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	/*
	 * Schedule the companion SP which will be busy in active wait. The
	 * secure interrupt will trigger in this window causing the companion
	 * SP to be preempted.
	 */
	res = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_YIELD_32);

	/*
	 * Attempt to communicate with target SP. SPMC shall return BUSY status.
	 */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_BUSY);
}

/**
 * This test aims to create a scenarios where a target endpoint aborts an
 * direct request from another secure endpoint in SPMC schedule mode.
 *
 * Initiator Endpoint must be Service1 SP since it owns the Secure Watchdog
 * timer interrupt.
 */
TEST(sp_lifecycle, sp_aborts_direct_req_in_spmc_mode)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *initiator_info = service1(mb.recv);
	struct ffa_partition_info *target_sp_info = service3(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	const uint32_t delay = 20;
	struct ffa_value res;

	/*
	 * Run target endpoint for it to wait for a request from Initiator
	 * endpoint and then voluntarily abort its execution using FFA_ABORT.
	 */
	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_dir_req", mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	/*
	 * Initiator endpoint runs in SPMC schedule mode in order to handle
	 * secure virtual interrupt and further sends direct request to target
	 * endpoint and expects it to be aborted.
	 */
	SERVICE_SELECT(initiator_info->vm_id, "sp_to_sp_dir_req_in_spmc_mode",
		       mb.send);

	/*
	 * Send to Initiator endpoint, the vm id of the target endpoint for its
	 * message.
	 */
	res = send_indirect_message(own_id, initiator_info->vm_id, mb.send,
				    &target_sp_info->vm_id,
				    sizeof(target_sp_info->vm_id), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_run(initiator_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	/*
	 * Send an indirect message to convey the Secure Watchdog timer delay
	 * which serves as the source of the secure interrupt.
	 */
	res = send_indirect_message(own_id, initiator_info->vm_id, mb.send,
				    &delay, sizeof(delay), 0);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	/* Schedule message receiver through FFA_RUN interface. */
	res = ffa_run(initiator_info->vm_id, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	/* Wait for the interrupt to trigger. */
	waitms(delay + 50);

	/*
	 * Attempt to communicate with target SP. SPMC shall return BUSY status.
	 */
	res = ffa_msg_send_direct_req(own_id, target_sp_info->vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * This test is orchestrated with help of two additional endpoints. The helper
 * endpoint sends a direct request message to target endpoint and expects it to
 * be aborted by target endpoint.
 * The target endpoints restarts execution after aborting itself. It is now
 * configured to run a new service. In order to perform robust checks on the
 * state of target endpoint, this test leverages a companion endpoint to simply
 * perform a echo handshake with target endpoint.
 *
 * Roles played by various endpoint to facilitate above test scenario:
 *    Helper endpoint     - Service1 SP
 *    Companion endpoint  - Service3 SP
 *    Target endpoint     - Either Service2 SP or Service4 SP
 */
void base_restart_sp_after_abort_direct_req(
	struct ffa_partition_info *target_sp_info, struct mailbox_buffers mb)
{
	struct ffa_partition_info *helper_info = service1(mb.recv);
	struct ffa_partition_info *companion_info = service3(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	/*
	 * Run target endpoint for it to wait for a request from helper endpoint
	 * and then voluntarily abort its execution using FFA_ABORT.
	 */
	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_dir_req", mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	/*
	 * The helper endpoint sends direct request to target endpoint and
	 * expects it to be aborted by target endpoint.
	 */
	SERVICE_SELECT(helper_info->vm_id, "sp_to_sp_dir_req_expect_to_abort",
		       mb.send);

	/* Send to helper endpoint the vm id of the target for its message. */
	res = send_indirect_message(own_id, helper_info->vm_id, mb.send,
				    &target_sp_info->vm_id,
				    sizeof(target_sp_info->vm_id), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);
	ffa_run(helper_info->vm_id, 0);

	/*
	 * By this time, target endpoint should have restarted. Prepare it with
	 * new workload which would be abort direct message again.
	 */
	dlog_verbose("Target endpoint should have restarted\n");

	SERVICE_SELECT(target_sp_info->vm_id, "sp_ffa_abort_dir_req", mb.send);
	ffa_run(target_sp_info->vm_id, 0);

	/*
	 * Allocate CPU cycles to helper endpoint to initiate direct request
	 * with target endpoint.
	 */
	ffa_run(helper_info->vm_id, 0);

	/*
	 * By this time, target endpoint should have restarted. Prepare it with
	 * new workload which would be simply echoing direct message.
	 */
	dlog_verbose("Target endpoint should have restarted\n");

	SERVICE_SELECT(target_sp_info->vm_id, "ffa_direct_message_resp_echo",
		       mb.send);
	/*
	 * Run target endpoint for it to wait for a request from helper
	 * endpoint.
	 */
	ffa_run(target_sp_info->vm_id, 0);

	/* Companion endpoint requests echo from target endpoint. */
	SERVICE_SELECT(companion_info->vm_id,
		       "ffa_direct_message_echo_services", mb.send);

	/*
	 * Send to companion endpoint the vm id of the target for its message.
	 */
	res = send_indirect_message(own_id, companion_info->vm_id, mb.send,
				    &target_sp_info->vm_id,
				    sizeof(target_sp_info->vm_id), 0);
	ASSERT_EQ(res.func, FFA_SUCCESS_32);

	ffa_run(companion_info->vm_id, 0);
}

/**
 * S-EL1 SP shall be restarted upon aborting. The test also ensures the
 * framework state of various endpoints is not corrupted.
 */
TEST(sp_lifecycle, sel1_sp_restart_after_abort_dir_req)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service2(mb.recv);

	base_restart_sp_after_abort_direct_req(target_sp_info, mb);
}

/**
 * S-EL0 SP shall be restarted upon aborting. The test also ensures the
 * framework state of various endpoints is not corrupted.
 */
TEST(sp_lifecycle, sel0_sp_restart_after_abort_dir_req)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service4(mb.recv);

	base_restart_sp_after_abort_direct_req(target_sp_info, mb);
}

/**
 * Check that SPMC can relinquish memory on behalf of an aborting partition.
 */
void base_sp_aborts_mem_lend_transaction(
	struct ffa_partition_info *target_sp_info,
	struct ffa_partition_info *companion_info, struct mailbox_buffers mb)
{
	struct ffa_value run_res;
	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)pages, .page_count = 1},
	};
	ffa_memory_handle_t handle;

	SERVICE_SELECT(target_sp_info->vm_id, "ffa_memory_retrieve_abort",
		       mb.send);
	SERVICE_SELECT(companion_info->vm_id, "ffa_memory_lend_relinquish",
		       mb.send);

	/* Lend the memory initially. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), target_sp_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	/*
	 * Let the memory be returned. The target partition is expected to
	 * abort.
	 */
	run_res = ffa_run(target_sp_info->vm_id, 0);
	EXPECT_FFA_ERROR(run_res, FFA_ABORTED);

	/*
	 * SPMC performs relinquishing on behalf of aborting partition. The
	 * reclaim request by owner shall succeed.
	 */
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);

	/* Share the memory with a different SP after it has been returned. */
	handle = send_memory_and_retrieve_request(
		FFA_MEM_LEND_32, mb.send, hf_vm_get_id(), companion_info->vm_id,
		constituents, ARRAY_SIZE(constituents), 0, 0,
		FFA_DATA_ACCESS_RW, FFA_DATA_ACCESS_RW,
		FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, FFA_INSTRUCTION_ACCESS_NX,
		FFA_MEMORY_NOT_SPECIFIED_MEM, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_CACHE_WRITE_BACK);

	run_res = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	EXPECT_EQ(ffa_mem_reclaim(handle, 0).func, FFA_SUCCESS_32);
}

/**
 * Check that SPMC can relinquish memory on behalf of an aborting S-EL0
 * partition.
 */
TEST(sp_lifecycle, sel0_sp_abort_nwd_mem_lend)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service1(mb.recv);
	struct ffa_partition_info *companion_info = service3(mb.recv);

	base_sp_aborts_mem_lend_transaction(target_sp_info, companion_info, mb);
}

/**
 * Check that SPMC can relinquish memory on behalf of an aborting S-EL1
 * partition.
 */
TEST(sp_lifecycle, sel1_sp_abort_nwd_mem_lend)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_sp_info = service3(mb.recv);
	struct ffa_partition_info *companion_info = service1(mb.recv);

	base_sp_aborts_mem_lend_transaction(target_sp_info, companion_info, mb);
}

/**
 * Check that SPMC can reclaim memory owned by an aborting partition.
 *
 * This test involves a target SP and a Companion SP. The target SP lends normal
 * memory to Companion SP and aborts. Companion SP retrieves, uses and
 * relinquishes the memory. The test ensures the Companion SP runs to
 * completion.
 */
static void base_sp_lend_to_sp_then_abort_reclaim_by_spmc(
	struct ffa_partition_info *target_info,
	struct ffa_partition_info *companion_info, struct mailbox_buffers mb)
{
	struct ffa_value ret;
	ffa_id_t companion_id = companion_info->vm_id;

	/* Configure target SP to lend memory to Companion SP and then abort. */
	SERVICE_SELECT(target_info->vm_id,
		       "ffa_lend_memory_to_companion_sp_and_abort", mb.send);

	/* Configure companion SP to retrieve then relinquish. */
	SERVICE_SELECT(companion_info->vm_id, "ffa_memory_retrieve_relinquish",
		       mb.send);

	/*
	 * Send companion ID to target SP so it can lend memory to Companion SP.
	 */
	ret = send_indirect_message(hf_vm_get_id(), target_info->vm_id, mb.send,
				    &companion_id, sizeof(companion_id), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Schedule target through FFA_RUN. It will lend to Companion SP. */
	ret = ffa_run(target_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Companion SP will have received retrieve; let it use and relinquish.
	 */
	ret = ffa_run(companion_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	/* Run target SP to allow it to abort. */
	ret = ffa_run(target_info->vm_id, 0);
	EXPECT_FFA_ERROR(ret, FFA_ABORTED);
}

TEST(sp_lifecycle, sel0_sp_lend_to_sp_then_abort_reclaim_by_spmc)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_info = service1(mb.recv);
	struct ffa_partition_info *companion_info = service3(mb.recv);

	base_sp_lend_to_sp_then_abort_reclaim_by_spmc(target_info,
						      companion_info, mb);
}

TEST(sp_lifecycle, sel1_sp_lend_to_sp_then_abort_reclaim_by_spmc)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *target_info = service3(mb.recv);
	struct ffa_partition_info *companion_info = service1(mb.recv);

	base_sp_lend_to_sp_then_abort_reclaim_by_spmc(target_info,
						      companion_info, mb);
}
