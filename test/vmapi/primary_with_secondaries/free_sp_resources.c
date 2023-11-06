/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define IRQ_ESPI_TEST_INTID 5000

/**
 * The aim of this test is to validate the functionality of SPMC to free
 * resources, such as interrupts, belonging to an aborted SP.
 * Get the S-EL0 Service1 partition to abort in runtime by writing to a memory
 * that was set to RO during initialisation.
 * Further, configure the service3 partition to trigger a secure interrupt that
 * targets the execution context of the aborted partition.
 */
TEST(free_sp_resources, secure_interrupt_targets_aborted_sp)
{
	struct mailbox_buffers mb = set_up_mailbox();
	uint32_t interrupt_id = IRQ_ESPI_TEST_INTID;
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value ret;

	SERVICE_SELECT(service1_info->vm_id, "ffa_mem_perm_set_ro_fails_write",
		       mb.send);
	EXPECT_EQ(ffa_run(service1_info->vm_id, 0).func, FFA_ERROR_32);

	/* Configure the partition to trigger a secure interrupt. */
	SERVICE_SELECT(service3_info->vm_id, "sip_call_trigger_spi", mb.send);

	/* Send a message containing the interrupt id to be triggered. */
	ret = send_indirect_message(own_id, service3_info->vm_id, mb.send,
				    &interrupt_id, sizeof(interrupt_id), 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	/*
	 * Allocate cycles to the S-EL1 Service3 partition. It should trigger
	 * the interrupt and yield control.
	 */
	ret = ffa_run(service3_info->vm_id, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
}
