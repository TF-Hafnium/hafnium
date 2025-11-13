/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/ffa_v1_0.h"

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "sp_helpers.h"

static void check_partition_info_descriptors(
	const struct ffa_partition_info *partitions, uint16_t count)
{
	struct ffa_uuid uuid;
	struct ffa_uuid image_uuid;

	EXPECT_EQ(count, 5);

	/* Expect the PVM in the first descriptor. */
	EXPECT_EQ(partitions[0].vm_id, hf_vm_get_id());
	EXPECT_TRUE(partitions[0].vcpu_count == 8);
	ffa_uuid_init(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[0].protocol_uuid, &uuid));
	EXPECT_EQ(partitions[0].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_DIRECT_REQ_SEND);

	/* Expect a primary SP in the second descriptor. */
	EXPECT_EQ(partitions[1].vm_id, SP_ID(1));
	EXPECT_EQ(partitions[1].vcpu_count, 1);
	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[1].protocol_uuid, &uuid));
	EXPECT_EQ(partitions[1].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_AARCH64_EXEC |
			  FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED |
			  FFA_PARTITION_LIVE_ACTIVATION);

	/* check for Image UUID needed for live activation. */
	ffa_uuid_init(0x962a7bf0, 0x174d471d, 0xa686c89e, 0x5c3e254e,
		      &image_uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[1].image_uuid, &image_uuid));

	/* Expect a secondary SP in the third descriptor. */
	EXPECT_EQ(partitions[2].vm_id, SP_ID(2));
	EXPECT_TRUE(partitions[2].vcpu_count == 8 ||
		    partitions[2].vcpu_count == 1);
	ffa_uuid_init(0xa609f132, 0x6b4f, 0x4c14, 0x9489, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[2].protocol_uuid, &uuid));
	EXPECT_EQ(partitions[2].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_AARCH64_EXEC |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED |
			  FFA_PARTITION_DIRECT_REQ2_RECV |
			  FFA_PARTITION_LIVE_ACTIVATION);

	ffa_uuid_init(0x2721ffc3, 0xf8a9417e, 0xa124af05, 0x7434a3af,
		      &image_uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[2].image_uuid, &image_uuid));

	/* Expect additional descriptor for the secondary SP. */
	EXPECT_EQ(partitions[3].vm_id, SP_ID(2));
	EXPECT_TRUE(partitions[3].vcpu_count == 8 ||
		    partitions[3].vcpu_count == 1);
	ffa_uuid_init(0x580940fa, 0x7e9d, 0x406f, 0x9aa2, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[3].protocol_uuid, &uuid));
	EXPECT_EQ(partitions[3].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_AARCH64_EXEC |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED |
			  FFA_PARTITION_DIRECT_REQ2_RECV |
			  FFA_PARTITION_LIVE_ACTIVATION);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[3].image_uuid, &image_uuid));

	/* Expect a tertiary SP in the fifth descriptor. */
	EXPECT_EQ(partitions[4].vm_id, SP_ID(3));
	EXPECT_EQ(partitions[4].vcpu_count, 8);
	ffa_uuid_init(0x1df938ef, 0xe8b94490, 0x84967204, 0xab77f4a5, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[4].protocol_uuid, &uuid));
	EXPECT_EQ(partitions[4].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_DIRECT_REQ_RECV |
			  FFA_PARTITION_INDIRECT_MSG);
}

TEST(partition_info_v1_3, ffa_partition_info_get_null_uuid)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid uuid;
	enum ffa_version version;

	/*
	 * First call FF-A version to tell the SPMC our version
	 * is v1.3.
	 */
	version = ffa_version(FFA_VERSION_1_3);
	EXPECT_EQ(version, FFA_VERSION_COMPILED);

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

	/* Expect five partitions descriptors. */
	EXPECT_EQ(ret.arg2, 5);

	/*
	 * Check the partition info descriptor size returned in w3 is
	 * correct.
	 */
	EXPECT_EQ(ret.arg3, sizeof(struct ffa_partition_info));
	check_partition_info_descriptors(partitions, (uint16_t)ret.arg2);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

TEST(partition_info_v1_3, ffa_partition_info_get_regs_null_uuid)
{
	struct ffa_value ret;
	uint16_t start_index = 0;
	struct ffa_uuid uuid;
	struct ffa_partition_info partitions[5];
	uint16_t last_index;
	uint16_t curr_index;
	uint16_t tag;
	uint16_t desc_size;
	enum ffa_version version;

	/*
	 * First call FF-A version to tell the SPMC our version
	 * is v1.3.
	 */
	version = ffa_version(FFA_VERSION_1_3);
	EXPECT_EQ(version, FFA_VERSION_COMPILED);

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

	/* Expect five partition descriptors in total. */
	EXPECT_EQ(last_index, 4);

	/* Expect 2 descriptors to be returned per invocation. */
	EXPECT_EQ(curr_index, 1);
	EXPECT_EQ(tag, 0);
	EXPECT_EQ(desc_size, sizeof(struct ffa_partition_info));

	ffa_partition_info_regs_get_part_info(ret, 0, &partitions[0]);
	ffa_partition_info_regs_get_part_info(ret, 1, &partitions[1]);

	start_index = 2;
	ret = ffa_partition_info_get_regs(&uuid, start_index, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_64);

	last_index = ffa_partition_info_regs_get_last_idx(ret);
	curr_index = ffa_partition_info_regs_get_curr_idx(ret);

	EXPECT_EQ(last_index, 4);
	EXPECT_EQ(curr_index, start_index + 1);
	ffa_partition_info_regs_get_part_info(ret, 0, &partitions[2]);
	ffa_partition_info_regs_get_part_info(ret, 1, &partitions[3]);

	start_index = 4;
	ret = ffa_partition_info_get_regs(&uuid, start_index, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_64);

	last_index = ffa_partition_info_regs_get_last_idx(ret);
	curr_index = ffa_partition_info_regs_get_curr_idx(ret);

	EXPECT_EQ(last_index, 4);
	EXPECT_EQ(curr_index, start_index);
	ffa_partition_info_regs_get_part_info(ret, 0, &partitions[4]);

	check_partition_info_descriptors(partitions,
					 (uint16_t)(last_index + 1));
}

TEST(partition_info_v1_3, ffa_partition_info_get_with_protocol_uuid)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid image_uuid;
	struct ffa_uuid uuid;
	enum ffa_version version;

	version = ffa_version(FFA_VERSION_1_3);
	EXPECT_EQ(version, FFA_VERSION_COMPILED);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();

	partitions = mb.recv;

	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);

	/* Check that expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Expect single Secure Partition. */
	EXPECT_EQ(ret.arg2, 1);

	/*
	 * Check the partition info descriptor size returned in w3 is
	 * correct.
	 */
	EXPECT_EQ(ret.arg3, sizeof(struct ffa_partition_info));

	/* Expect a primary SP's properties to be returned. */
	EXPECT_EQ(partitions[0].vm_id, SP_ID(1));
	EXPECT_EQ(partitions[0].vcpu_count, 1);

	/*
	 * Protocol UUID must not be populated in partition descriptor when
	 * specified as input to the ABI.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[0].protocol_uuid, &uuid));
	EXPECT_EQ(partitions[0].properties,
		  FFA_PARTITION_DIRECT_REQ_RECV | FFA_PARTITION_AARCH64_EXEC |
			  FFA_PARTITION_INDIRECT_MSG |
			  FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_VM_CREATED |
			  FFA_PARTITION_VM_DESTROYED |
			  FFA_PARTITION_LIVE_ACTIVATION);

	ffa_uuid_init(0x962a7bf0, 0x174d471d, 0xa686c89e, 0x5c3e254e,
		      &image_uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[0].image_uuid, &image_uuid));
}

TEST(partition_info_v1_3, ffa_partition_info_get_regs_with_protocol_uuid)
{
	struct ffa_value ret;
	struct ffa_partition_info partition;
	struct ffa_uuid image_uuid;
	struct ffa_uuid uuid;
	uint16_t start_index = 0;
	uint16_t last_index;
	uint16_t curr_index;
	uint16_t tag;
	uint16_t desc_size;

	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);

	/* Check that expected partition information is returned. */
	ret = ffa_partition_info_get_regs(&uuid, start_index, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_64);

	last_index = ffa_partition_info_regs_get_last_idx(ret);
	curr_index = ffa_partition_info_regs_get_curr_idx(ret);
	tag = ffa_partition_info_regs_get_tag(ret);
	desc_size = ffa_partition_info_regs_get_desc_size(ret);

	/* Expect single Secure Partition. */
	EXPECT_EQ(last_index, 0);
	EXPECT_EQ(curr_index, 0);
	EXPECT_EQ(tag, 0);

	/* Check the partition info descriptor size is correct. */
	EXPECT_EQ(desc_size, sizeof(struct ffa_partition_info));

	ffa_partition_info_regs_get_part_info(ret, 0, &partition);

	/* Expect a primary SP's properties to be returned. */
	EXPECT_EQ(partition.vm_id, SP_ID(1));
	EXPECT_EQ(partition.vcpu_count, 1);

	/*
	 * Protocol UUID must not be populated in partition descriptor when
	 * specified as input to the ABI.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partition.protocol_uuid, &uuid));
	EXPECT_EQ(partition.properties, FFA_PARTITION_DIRECT_REQ_RECV |
						FFA_PARTITION_AARCH64_EXEC |
						FFA_PARTITION_INDIRECT_MSG |
						FFA_PARTITION_NOTIFICATION |
						FFA_PARTITION_VM_CREATED |
						FFA_PARTITION_VM_DESTROYED |
						FFA_PARTITION_LIVE_ACTIVATION);

	ffa_uuid_init(0x962a7bf0, 0x174d471d, 0xa686c89e, 0x5c3e254e,
		      &image_uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partition.image_uuid, &image_uuid));
}
