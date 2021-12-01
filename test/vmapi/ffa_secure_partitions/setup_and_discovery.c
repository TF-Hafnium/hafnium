/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

TEST(ffa, ffa_partition_info_get_uuid_null)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid uuid;

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/*
	 * A Null UUID requests information for all partitions
	 * including VMs and SPs.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Check that expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect two partitions. */
	EXPECT_EQ(ret.arg2, 2);

	/* Expect the PVM as first partition. */
	EXPECT_EQ(partitions[0].vm_id, hf_vm_get_id());
	EXPECT_EQ(partitions[0].vcpu_count, 8);

	/* Expect a SP as second partition. */
	EXPECT_EQ(partitions[1].vm_id, SP_ID(1));
	EXPECT_EQ(partitions[1].vcpu_count, 8);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(ffa, ffa_partition_info_get_uuid_fixed)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid uuid;

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/* Search for a known secure partition UUID. */
	ffa_uuid_init(0xa609f132, 0x6b4f, 0x4c14, 0x9489, &uuid);

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect one partition. */
	EXPECT_EQ(ret.arg2, 1);

	/* Expect a secure partition. */
	EXPECT_EQ(partitions[0].vm_id, HF_SPMC_VM_ID + 1);
	EXPECT_EQ(partitions[0].vcpu_count, 8);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(ffa, ffa_partition_info_get_uuid_unknown)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	/* Search for a unknown partition UUID. */
	ffa_uuid_init(1, 1, 1, 1, &uuid);

	/* Expect no partition is found with such UUID. */
	ret = ffa_partition_info_get(&uuid);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
}

/*
 * Check FFA_SPM_ID_GET response.
 * DEN0077A FF-A v1.1 Beta0 section 13.9 FFA_SPM_ID_GET.
 */
TEST(ffa, ffa_spm_id_get)
{
	struct ffa_value ret = ffa_spm_id_get();

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect the SPMC FF-A ID at NS virtual FF-A instance. */
	EXPECT_EQ(ret.arg2, HF_SPMC_VM_ID);
}
