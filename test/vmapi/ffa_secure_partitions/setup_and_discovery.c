/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_v1_0.h"

#include "vmapi/hf/call.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(ffa)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

static void check_v1_1_partition_info_descriptors(
	const struct ffa_partition_info *partitions)
{
	struct ffa_uuid uuid;

	/* Expect the PVM as first partition. */
	EXPECT_EQ(partitions[0].vm_id, hf_vm_get_id());
	EXPECT_EQ(partitions[0].vcpu_count, 8);
	ffa_uuid_init(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[0].uuid, &uuid));
	EXPECT_EQ(partitions[0].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_DIRECT_REQ_SEND);

	/* Expect a primary SP as second partition. */
	EXPECT_EQ(partitions[1].vm_id, SP_ID(1));
	EXPECT_TRUE(partitions[1].vcpu_count == 8 ||
		    partitions[1].vcpu_count == 1);
	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[1].uuid, &uuid));
	EXPECT_EQ(partitions[1].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_DIRECT_REQ_RECV |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED);

	/* Expect a secondary SP as third partition. */
	EXPECT_EQ(partitions[2].vm_id, SP_ID(2));
	EXPECT_TRUE(partitions[1].vcpu_count == 8 ||
		    partitions[1].vcpu_count == 1);
	ffa_uuid_init(0xa609f132, 0x6b4f, 0x4c14, 0x9489, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[2].uuid, &uuid));
	EXPECT_EQ(partitions[2].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_AARCH64_EXEC |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED |
			  FFA_PARTITION_DIRECT_REQ2_RECV);

	/* Expect a tertiary SP as fourth partition. */
	EXPECT_EQ(partitions[3].vm_id, SP_ID(3));
	EXPECT_TRUE(partitions[3].vcpu_count == 8);
	ffa_uuid_init(0x1df938ef, 0xe8b94490, 0x84967204, 0xab77f4a5, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[3].uuid, &uuid));
	EXPECT_EQ(partitions[3].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_DIRECT_REQ_RECV |
			  FFA_PARTITION_INDIRECT_MSG);
}

TEST(ffa, ffa_partition_info_get_regs_sp_test)
{
	const ffa_id_t receiver_id = SP_ID(1);
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_check_partition_info_get_regs_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

TEST(ffa, ffa_partition_info_get_regs_uuid_null)
{
	struct ffa_value ret;
	uint16_t start_index = 0;
	struct ffa_uuid uuid;
	struct ffa_partition_info partition_info[4];
	uint16_t last_index;
	uint16_t curr_index;
	uint16_t tag;
	uint16_t desc_size;

	/*
	 * A Null UUID requests information for all partitions
	 * including VMs and SPs.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Check that expected partition information is returned. */
	ret = ffa_partition_info_get_regs(&uuid, start_index, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_64);

	last_index = ffa_partition_info_regs_get_last_idx(ret);
	curr_index = ffa_partition_info_regs_get_curr_idx(ret);
	tag = ffa_partition_info_regs_get_tag(ret);
	desc_size = ffa_partition_info_regs_get_desc_size(ret);

	/* Expect four partitions, one VM (primary), three SPs) */
	EXPECT_EQ(last_index, 3);
	EXPECT_EQ(curr_index, 3);
	EXPECT_EQ(tag, 0);
	EXPECT_EQ(desc_size, sizeof(struct ffa_partition_info));

	ffa_partition_info_regs_get_part_info(ret, 0, &partition_info[0]);
	ffa_partition_info_regs_get_part_info(ret, 1, &partition_info[1]);
	ffa_partition_info_regs_get_part_info(ret, 2, &partition_info[2]);
	ffa_partition_info_regs_get_part_info(ret, 3, &partition_info[3]);

	check_v1_1_partition_info_descriptors(partition_info);
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
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect four partitions. */
	EXPECT_EQ(ret.arg2, 4);

	/*
	 * Check the partition info descriptor size returned in w3 is
	 * correct.
	 */
	EXPECT_EQ(ret.arg3, sizeof(struct ffa_partition_info));

	/* Expect the PVM as first partition. */
	check_v1_1_partition_info_descriptors(partitions);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(ffa, ffa_partition_info_get_count_flag)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect four partitions. */
	EXPECT_EQ(ret.arg2, 4);

	/* Check when the count flag is set w3 MBZ. */
	EXPECT_EQ(ret.arg3, 0);
}

TEST(ffa, ffa_partition_info_get_flags_mbz_fail)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid, 0xffff);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
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

	/* Check that a partition count of 1 is returned. */
	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect one partition. */
	EXPECT_EQ(ret.arg2, 1);

	/* Check when the count flag is set w3 MBZ. */
	EXPECT_EQ(ret.arg3, 0);

	/* And that the buffer is zero */
	EXPECT_EQ(partitions[0].vm_id, 0);
	EXPECT_EQ(partitions[0].vcpu_count, 0);

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect one partition. */
	EXPECT_EQ(ret.arg2, 1);

	/*
	 * Check the partition info descriptor size returned in w3 is
	 * correct.
	 */
	EXPECT_EQ(ret.arg3, sizeof(struct ffa_partition_info));

	/* Expect a secure partition. */
	EXPECT_EQ(partitions[0].vm_id, HF_SPMC_VM_ID + 2);
	EXPECT_TRUE(partitions[0].vcpu_count == 8 ||
		    partitions[0].vcpu_count == 1);
	EXPECT_EQ(partitions[0].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_AARCH64_EXEC |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED |
			  FFA_PARTITION_DIRECT_REQ2_RECV);

	/*
	 * If a uuid is specified (not null) ensure the uuid returned in the
	 * partition info descriptor is zeroed.
	 */
	EXPECT_TRUE(ffa_uuid_is_null(&partitions[0].uuid));

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(ffa, ffa_partition_info_get_uuid_unknown)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	/* Search for a unknown partition UUID. */
	ffa_uuid_init(1, 1, 1, 1, &uuid);

	/* Expect no partition is found with such UUID. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
}

TEST(ffa, ffa_partition_info_get_v1_0_descriptors)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info_v1_0 *partitions_v1_0;
	struct ffa_uuid uuid;
	enum ffa_version version;

	/*
	 * First call FF-A version to tell the SPMC our version
	 * is v1.0.
	 */
	version = ffa_version(FFA_VERSION_1_0);
	EXPECT_EQ(version, FFA_VERSION_COMPILED);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();

	partitions_v1_0 = mb.recv;

	/*
	 * A Null UUID requests information for all partitions
	 * including VMs and SPs.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Check that expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect four partitions. */
	EXPECT_EQ(ret.arg2, 4);

	/*
	 * Check the partition info descriptor size returned in w3 is
	 * correct.
	 */
	EXPECT_EQ(ret.arg3, sizeof(struct ffa_partition_info_v1_0));

	/* Expect the PVM as first partition. */
	EXPECT_EQ(partitions_v1_0[0].vm_id, hf_vm_get_id());
	EXPECT_TRUE(partitions_v1_0[0].vcpu_count == 8 ||
		    partitions_v1_0[0].vcpu_count == 1);
	EXPECT_EQ(partitions_v1_0[0].properties,
		  FFA_PARTITION_DIRECT_REQ_SEND | FFA_PARTITION_INDIRECT_MSG);
	EXPECT_EQ(partitions_v1_0[0].properties & FFA_PARTITION_v1_0_RES_MASK,
		  0);

	/* Expect a primary SP as second partition. */
	EXPECT_EQ(partitions_v1_0[1].vm_id, SP_ID(1));
	EXPECT_EQ(partitions_v1_0[1].vcpu_count, 8);
	EXPECT_EQ(partitions_v1_0[1].properties, FFA_PARTITION_DIRECT_REQ_RECV);
	EXPECT_EQ(partitions_v1_0[1].properties & FFA_PARTITION_v1_0_RES_MASK,
		  0);

	/* Expect a secondary SP as third partition. */
	EXPECT_EQ(partitions_v1_0[2].vm_id, SP_ID(2));
	EXPECT_TRUE(partitions_v1_0[2].vcpu_count == 8 ||
		    partitions_v1_0[2].vcpu_count == 1);
	EXPECT_EQ(partitions_v1_0[2].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_INDIRECT_MSG);
	EXPECT_EQ(partitions_v1_0[2].properties & FFA_PARTITION_v1_0_RES_MASK,
		  0);

	/* Expect a tertiary SP as fourth partition. */
	EXPECT_EQ(partitions_v1_0[3].vm_id, SP_ID(3));
	EXPECT_EQ(partitions_v1_0[3].vcpu_count, 8);
	EXPECT_EQ(partitions_v1_0[3].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_INDIRECT_MSG);
	EXPECT_EQ(partitions_v1_0[3].properties & FFA_PARTITION_v1_0_RES_MASK,
		  0);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
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

TEST_PRECONDITION(ffa, npi_not_supported, service2_is_el0)
{
	const ffa_id_t own_id = hf_vm_get_id();
	/* SP is expected to be S-EL0 partition */
	const ffa_id_t receiver_id = SP_ID(2);
	struct ffa_value res;

	res = sp_ffa_features_cmd_send(own_id, receiver_id, FFA_FEATURE_NPI);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, FFA_ERROR_32);
	EXPECT_EQ((int32_t)res.arg4, FFA_NOT_SUPPORTED);
}

TEST_PRECONDITION(ffa, secondary_ep_register_supported, service2_is_mp_sp)
{
	const ffa_id_t own_id = hf_vm_get_id();
	/* SP is expected to be S-EL0 partition */
	const ffa_id_t receiver_id = SP_ID(2);
	struct ffa_value res;

	res = sp_ffa_features_cmd_send(own_id, receiver_id,
				       FFA_SECONDARY_EP_REGISTER_64);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, FFA_SUCCESS_32);
}

TEST_PRECONDITION(ffa, secondary_ep_register_not_supported, service2_is_up_sp)
{
	const ffa_id_t own_id = hf_vm_get_id();
	/* SP is expected to be S-EL0 partition */
	const ffa_id_t receiver_id = SP_ID(2);
	struct ffa_value res;

	res = sp_ffa_features_cmd_send(own_id, receiver_id,
				       FFA_SECONDARY_EP_REGISTER_64);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, FFA_ERROR_32);
	EXPECT_EQ((int32_t)res.arg4, FFA_NOT_SUPPORTED);
}
