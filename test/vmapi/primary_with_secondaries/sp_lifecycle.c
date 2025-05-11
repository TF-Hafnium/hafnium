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
