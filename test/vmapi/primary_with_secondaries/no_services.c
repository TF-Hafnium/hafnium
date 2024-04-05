/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/ffa_v1_0.h"
#include "hf/mm.h"
#include "hf/static_assert.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
static alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];
static_assert(sizeof(send_page) == PAGE_SIZE, "Send page is not a page.");
static_assert(sizeof(recv_page) == PAGE_SIZE, "Recv page is not a page.");

static hf_ipaddr_t send_page_addr = (hf_ipaddr_t)send_page;
static hf_ipaddr_t recv_page_addr = (hf_ipaddr_t)recv_page;

/**
 * Confirms the primary VM has the primary ID.
 */
TEST(hf_vm_get_id, primary_has_primary_id)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);
}

TEAR_DOWN(ffa_partition_info_get)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * Confirm there are 3 secondary VMs as well as this primary VM, and that they
 * have the expected number of vCPUs.
 */
TEST(ffa_partition_info_get, three_secondary_vms)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_uuid uuid;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Try to get partition information before the RX buffer is setup. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	/* Only getting the partition count should succeed however. */
	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg2, 4);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	/* Confirm there are 3 FF-A partitions, one with 2 UUIDs. */
	EXPECT_EQ(ret.arg2, 4);

	/* The first two secondary VMs should have 1 vCPU, the other one 2. */
	EXPECT_EQ(partitions[0].vcpu_count, 8);
	EXPECT_EQ(partitions[1].vcpu_count, 8);
	EXPECT_EQ(partitions[2].vcpu_count, 8);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

/**
 * Confirm that it is an error to get partition info for a nonexistent VM.
 */
TEST(ffa_partition_info_get, invalid_vm_uuid)
{
	struct ffa_value ret;
	struct ffa_uuid uuid;

	/* Try to get partition information for an unrecognized UUID. */
	ffa_uuid_init(0, 0, 0, 1, &uuid);

	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

TEST(ffa_partition_info_get, get_v1_0_descriptor)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info_v1_0 *partitions;
	struct ffa_uuid uuid;

	/* Set ffa_version to v1.0. */
	EXPECT_EQ(ffa_version(FFA_VERSION_1_0), FFA_VERSION_COMPILED);

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Try to get partition information before the RX buffer is setup. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	/* Only getting the partition count should succeed however. */
	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Confirm there are 3 secondary VMs, one with 2 UUIDs. */
	EXPECT_EQ(ret.arg2, 4);

	EXPECT_EQ(partitions[0].vcpu_count, 8);
	EXPECT_EQ(partitions[1].vcpu_count, 8);
	EXPECT_EQ(partitions[2].vcpu_count, 8);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

/**
 * The primary can't be run by the hypervisor.
 */
TEST(ffa_run, cannot_run_primary)
{
	struct ffa_value res = ffa_run(HF_PRIMARY_VM_ID, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Can only run a VM that exists.
 */
TEST(ffa_run, cannot_run_absent_secondary)
{
	struct ffa_value res = ffa_run(1234, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Can only run a vCPU that exists.
 */
TEST(ffa_run, cannot_run_absent_vcpu)
{
	struct ffa_value res = ffa_run(SERVICE_VM1, 1234);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

TEAR_DOWN(ffa_rxtx_map)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * The configured send/receive addresses can't be device memory.
 */
TEST(ffa_rxtx_map, fails_with_device_memory)
{
	EXPECT_FFA_ERROR(ffa_rxtx_map(PAGE_SIZE, PAGE_SIZE * 2),
			 FFA_INVALID_PARAMETERS);
}

/**
 * The configured send/receive addresses can't be unaligned.
 */
TEST(ffa_rxtx_map, fails_with_unaligned_pointer)
{
	uint8_t maybe_aligned[2];
	hf_ipaddr_t unaligned_addr = (hf_ipaddr_t)&maybe_aligned[1];
	hf_ipaddr_t aligned_addr = (hf_ipaddr_t)send_page;

	/* Check that the address is unaligned. */
	ASSERT_EQ(unaligned_addr & 1, 1);

	EXPECT_FFA_ERROR(ffa_rxtx_map(aligned_addr, unaligned_addr),
			 FFA_INVALID_PARAMETERS);
	EXPECT_FFA_ERROR(ffa_rxtx_map(unaligned_addr, aligned_addr),
			 FFA_INVALID_PARAMETERS);
	EXPECT_FFA_ERROR(ffa_rxtx_map(unaligned_addr, unaligned_addr),
			 FFA_INVALID_PARAMETERS);
}

/**
 * The configured send/receive addresses can't be the same page.
 */
TEST(ffa_rxtx_map, fails_with_same_page)
{
	EXPECT_FFA_ERROR(ffa_rxtx_map(send_page_addr, send_page_addr),
			 FFA_INVALID_PARAMETERS);
	EXPECT_FFA_ERROR(ffa_rxtx_map(recv_page_addr, recv_page_addr),
			 FFA_INVALID_PARAMETERS);
}

/**
 * The configuration of the send/receive addresses can only happen once.
 */
TEST(ffa_rxtx_map, fails_if_already_succeeded)
{
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	EXPECT_FFA_ERROR(ffa_rxtx_map(send_page_addr, recv_page_addr),
			 FFA_DENIED);
}

/**
 * The configuration of the send/receive address is successful with valid
 * arguments.
 */
TEST(ffa_rxtx_map, succeeds)
{
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
}

/**
 * The primary receives messages from ffa_run().
 */
TEST(hf_mailbox_receive, cannot_receive_from_primary_blocking)
{
	struct ffa_value res = ffa_msg_wait();
	EXPECT_NE(res.func, FFA_SUCCESS_32);
}

/**
 * The primary receives messages from ffa_run().
 */
TEST(hf_mailbox_receive, cannot_receive_from_primary_non_blocking)
{
	struct ffa_value res = ffa_msg_poll();
	EXPECT_NE(res.func, FFA_SUCCESS_32);
}

/**
 * The buffer pair can be successfully unmapped from a VM that has
 * just created the mapping.
 */
TEST(ffa_rxtx_unmap, succeeds)
{
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
}

/**
 * Unmap will fail if no mapping exists for the VM.
 */
TEST(ffa_rxtx_unmap, fails_if_no_mapping)
{
	EXPECT_FFA_ERROR(ffa_rxtx_unmap(), FFA_INVALID_PARAMETERS);
}

/**
 * A buffer pair cannot be unmapped multiple times.
 */
TEST(ffa_rxtx_unmap, fails_if_already_unmapped)
{
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_FFA_ERROR(ffa_rxtx_unmap(), FFA_INVALID_PARAMETERS);
}

/**
 * Test we can remap a region after it has been unmapped.
 */
TEST(ffa_rxtx_unmap, succeeds_in_remapping_region)
{
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
}

/**
 * The `allocator_id` must be 0 at virtual instances.
 */
TEST(ffa_rxtx_unmap, validate_allocator_id)
{
	struct ffa_value ret;

	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);

	/* Set the `allocator_id`, which MBZ at virtual instances. */
	ret = ffa_call(
		(struct ffa_value){.func = FFA_RXTX_UNMAP_32,
				   .arg1 = 1ULL << FFA_RXTX_ALLOCATOR_SHIFT});
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);

	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
}
