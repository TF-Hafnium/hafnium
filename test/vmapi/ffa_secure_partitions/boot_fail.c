/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define SP2_ESPI_TEST_INTID 5000

/*
 * The following is a precondition function, for the current system set-up.
 * Check that SP 1 is configured to fail at boot in this setup.
 */
bool sp1_fail_at_boot(void)
{
	return (FAILING_SP == 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that SP 2 is configured to fail at boot in this setup.
 */
bool sp2_fail_at_boot(void)
{
	return (FAILING_SP == 2);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that SP 3 is configured to fail at boot in this setup.
 */
bool sp3_fail_at_boot(void)
{
	return (FAILING_SP == 3);
}

static void nwd_to_sp_echo(ffa_id_t receiver_id)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
			       msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);
}
/**
 * This test uses a setup in which the SP providing service1 reports an error
 * during initialization. The test checks that the SP returns an error with
 * FFA_ABORTED error code when ffa_run attempts to allocate CPU cycles to the
 * aborted SP.
 *
 * It also ensure that the subsequent services (2 and 3) are still
 * able to successfully boot by performing a direct message/direct response
 * echo test.
 */
TEST_PRECONDITION(boot_fail, sp1_fails_to_init, sp1_fail_at_boot)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	struct ffa_value ret;

	ret = ffa_run(service1_info->vm_id, 0);
	EXPECT_FFA_ERROR(ret, FFA_ABORTED);

	nwd_to_sp_echo(service2_info->vm_id);
	nwd_to_sp_echo(service3_info->vm_id);
}

/**
 * This test uses a setup in which the SP providing service2 reports an error
 * during initialization. The test checks that SP 2 returns an error with
 * FFA_ABORTED error code when ffa_run attempts to allocate CPU cycles to the
 * aborted SP.
 *
 * It also ensure that the other services, (1 and 3) are still
 * able to successfully boot by performing a direct message/direct response
 * echo test.
 */
TEST_PRECONDITION(boot_fail, sp2_fails_to_init, sp2_fail_at_boot)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	struct ffa_value ret;

	ret = ffa_run(service2_info->vm_id, 0);
	EXPECT_FFA_ERROR(ret, FFA_ABORTED);

	nwd_to_sp_echo(service1_info->vm_id);
	nwd_to_sp_echo(service3_info->vm_id);
}

/**
 * This test is an extension of the prior test, sp2_fails_to_init. It aims to
 * validate the functionality of SPMC to reclaim resources, such as interrupts,
 * belonging to an aborted SP. It does so by sending a command to SP1 to pend
 * an espi interrupt belonging to the aborted SP2.
 *
 * The SPMC shall not resume the execution context of aborted SP2. Similar to
 * the prior test, it ensures SP1 and SP3 boot successfully by performing echo
 * tests.
 */
TEST_PRECONDITION(boot_fail, secure_interrupt_targets_aborted_sp2,
		  sp2_fail_at_boot)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	struct ffa_value ret;

	ret = sp_trigger_espi_cmd_send(hf_vm_get_id(), service1_info->vm_id,
				       SP2_ESPI_TEST_INTID);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(ret), SP_SUCCESS);

	nwd_to_sp_echo(service1_info->vm_id);
	nwd_to_sp_echo(service3_info->vm_id);

	/* The aborted SP shall not be resumed by a direct request message. */
	ret = sp_get_last_interrupt_cmd_send(hf_vm_get_id(),
					     service2_info->vm_id);
	EXPECT_FFA_ERROR(ret, FFA_ABORTED);
}

/**
 * This test uses a setup in which the SP providing service3 reports an error
 * during initialization. The test checks that SP 3 returns an error with
 * FFA_ABORTED error code when ffa_run attempts to allocate CPU cycles to the
 * aborted SP.
 *
 * It also ensure that the other services (1 and 2) are still
 * able to successfully boot by performing a direct message/direct response
 * echo test.
 */
TEST_PRECONDITION(boot_fail, sp3_fails_to_init, sp3_fail_at_boot)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	struct ffa_value ret;

	ret = ffa_run(service3_info->vm_id, 0);
	EXPECT_FFA_ERROR(ret, FFA_ABORTED);

	nwd_to_sp_echo(service1_info->vm_id);
	nwd_to_sp_echo(service2_info->vm_id);
}

/**
 * This test confirms that an service which has been aborted due to an
 * initilaization failure cannot be resumed by a direct messaging interface.
 */
TEST_PRECONDITION(boot_fail, dir_msg_to_failed_sp, sp1_fail_at_boot)
{
	const uint32_t msg[] = {0x22223333, 0x44445555, 0x66667777, 0x88889999};
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value ret;
	ffa_id_t own_id = hf_vm_get_id();

	ret = sp_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
			       msg[3]);

	EXPECT_FFA_ERROR(ret, FFA_ABORTED);
}
