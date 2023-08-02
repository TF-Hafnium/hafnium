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

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static void sp_check_partition_info_get_regs_null_uuid(void)
{
	struct ffa_value ret;
	uint16_t start_index = 0;
	struct ffa_uuid uuid;
	struct ffa_partition_info partitions[2];
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

	/* Expect two partitions (2 SPs) */
	EXPECT_EQ(last_index, 1);
	EXPECT_EQ(curr_index, 1);
	EXPECT_EQ(tag, 0);
	EXPECT_EQ(desc_size, sizeof(struct ffa_partition_info));

	ffa_partition_info_regs_get_part_info(ret, 0, &partitions[0]);
	ffa_partition_info_regs_get_part_info(ret, 1, &partitions[1]);

	EXPECT_EQ(partitions[0].vm_id, SP_ID(1));
	EXPECT_EQ(partitions[0].vcpu_count, 8);
	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[0].uuid, &uuid));
	EXPECT_EQ(partitions[0].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_DIRECT_REQ_RECV |
			  FFA_PARTITION_DIRECT_REQ_SEND);

	EXPECT_EQ(partitions[1].vm_id, SP_ID(2));
	EXPECT_TRUE(partitions[1].vcpu_count == 8 ||
		    partitions[1].vcpu_count == 1);
	ffa_uuid_init(0xa609f132, 0x6b4f, 0x4c14, 0x9489, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions[1].uuid, &uuid));
	EXPECT_EQ(partitions[1].properties,
		  FFA_PARTITION_AARCH64_EXEC | FFA_PARTITION_NOTIFICATION |
			  FFA_PARTITION_DIRECT_REQ_RECV |
			  FFA_PARTITION_DIRECT_REQ_SEND);
}

static void sp_check_partition_info_get_regs_uuid(void)
{
	struct ffa_value ret;
	uint16_t start_index = 0;
	struct ffa_uuid uuid;
	struct ffa_partition_info partitions;
	uint16_t last_index;
	uint16_t curr_index;
	uint16_t tag;
	uint16_t desc_size;

	/*
	 * Get info for UUID of SP_ID(1)
	 */
	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);

	ret = ffa_partition_info_get_regs(&uuid, start_index, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_64);

	last_index = ffa_partition_info_regs_get_last_idx(ret);
	curr_index = ffa_partition_info_regs_get_curr_idx(ret);
	tag = ffa_partition_info_regs_get_tag(ret);
	desc_size = ffa_partition_info_regs_get_desc_size(ret);

	EXPECT_EQ(last_index, 0);
	EXPECT_EQ(curr_index, 0);
	EXPECT_EQ(tag, 0);
	EXPECT_EQ(desc_size, sizeof(struct ffa_partition_info));

	ffa_partition_info_regs_get_part_info(ret, 0, &partitions);

	EXPECT_EQ(partitions.vm_id, SP_ID(1));
	EXPECT_EQ(partitions.vcpu_count, 8);
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions.uuid, &uuid));
	EXPECT_EQ(partitions.properties, FFA_PARTITION_AARCH64_EXEC |
						 FFA_PARTITION_NOTIFICATION |
						 FFA_PARTITION_DIRECT_REQ_RECV |
						 FFA_PARTITION_DIRECT_REQ_SEND);
}

static void sp_check_partition_info_get_regs_tag_not_zero(void)
{
	struct ffa_value ret;
	uint16_t start_index = 0;
	struct ffa_uuid uuid;

	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);
	ret = ffa_partition_info_get_regs(&uuid, start_index, 0xF);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_FFA_ERROR(ret, FFA_RETRY);
}

static void sp_check_partition_info_get_regs_invalid_uuid(void)
{
	struct ffa_value ret;
	uint16_t start_index = 0;
	struct ffa_uuid uuid;
	ffa_uuid_init(0xDEAD, 0xBEEF, 0xBEEF, 0xDEAD, &uuid);
	ret = ffa_partition_info_get_regs(&uuid, start_index, 0);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

static void sp_check_partition_info_get_regs_bad_start_idx(void)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	/*
	 * Get info for UUID of SP_ID(2). start_index can only be 0 since
	 * there is only one entry that should be found.
	 */
	ffa_uuid_init(0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, &uuid);
	ret = ffa_partition_info_get_regs(&uuid, 1, 0);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	/*
	 * Get all entries (2 entries for 2 SPs). start_index can only be 0 or
	 * 1 corresponding to the 2 entries.
	 */
	ffa_uuid_init(0, 0, 0, 0, &uuid);
	ret = ffa_partition_info_get_regs(&uuid, 2, 0);
	EXPECT_EQ(ret.func, FFA_ERROR_32);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

static void sp_check_partition_info_get_regs_start_idx(void)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;
	struct ffa_partition_info partitions;
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
	ret = ffa_partition_info_get_regs(&uuid, 1, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_64);

	last_index = ffa_partition_info_regs_get_last_idx(ret);
	curr_index = ffa_partition_info_regs_get_curr_idx(ret);
	tag = ffa_partition_info_regs_get_tag(ret);
	desc_size = ffa_partition_info_regs_get_desc_size(ret);

	EXPECT_EQ(last_index, 1);
	EXPECT_EQ(curr_index, 1);
	EXPECT_EQ(tag, 0);
	EXPECT_EQ(desc_size, sizeof(struct ffa_partition_info));

	ffa_partition_info_regs_get_part_info(ret, 0, &partitions);

	EXPECT_EQ(partitions.vm_id, SP_ID(2));
	EXPECT_TRUE(partitions.vcpu_count == 8 || partitions.vcpu_count == 1);
	ffa_uuid_init(0xa609f132, 0x6b4f, 0x4c14, 0x9489, &uuid);
	EXPECT_TRUE(ffa_uuid_equal(&partitions.uuid, &uuid));
	EXPECT_EQ(partitions.properties, FFA_PARTITION_AARCH64_EXEC |
						 FFA_PARTITION_NOTIFICATION |
						 FFA_PARTITION_DIRECT_REQ_RECV |
						 FFA_PARTITION_DIRECT_REQ_SEND);
}

struct ffa_value sp_check_partition_info_get_regs_cmd(ffa_id_t test_source)
{
	ffa_id_t own_id = hf_vm_get_id();

	sp_check_partition_info_get_regs_null_uuid();
	sp_check_partition_info_get_regs_uuid();
	sp_check_partition_info_get_regs_tag_not_zero();
	sp_check_partition_info_get_regs_invalid_uuid();
	sp_check_partition_info_get_regs_bad_start_idx();
	sp_check_partition_info_get_regs_start_idx();

	return sp_success(own_id, test_source, 0);
}
