/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/ffa_v1_0.h"
#include "hf/mm.h"
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

/* Multi-page buffers for testing dynamic RXTX buffer sizes. */
static alignas(PAGE_SIZE) uint8_t
	send_pages_max[FFA_PAGE_SIZE * FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT];
static alignas(PAGE_SIZE) uint8_t
	recv_pages_max[FFA_PAGE_SIZE * FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT];

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
	/* Set ffa_version to v1.2. */
	EXPECT_EQ(ffa_version(FFA_VERSION_1_2), FFA_VERSION_COMPILED);

	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions;
	struct ffa_partition_info_v1_1 partition_info_v1_1[5];
	struct ffa_uuid uuid;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Try to get partition information before the RX buffer is setup. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	/* Only getting the partition count should succeed however. */
	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg2, 5);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Confirm there are 3 FF-A partitions, two with 2 UUIDs. */
	EXPECT_EQ(ret.arg2, 5);

	partition_info_convert_to_v1_1_format(partitions, partition_info_v1_1,
					      ret);

	/* Check for the correct vCPU count for each endpoint. */
	EXPECT_EQ(partition_info_v1_1[0].vcpu_count, 8);
	EXPECT_EQ(partition_info_v1_1[1].vcpu_count, 8);
	EXPECT_EQ(partition_info_v1_1[2].vcpu_count, 8);

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

	/*
	 * Confirm there are 3 secondary VMs, since we are v1.0 we only expect
	 * one UUID per VM.
	 */
	EXPECT_EQ(ret.arg2, 3);

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
 * Multi-page RXTX_MAP succeeds with the maximum supported page count.
 *
 * Only meaningful when RXTX_MAX_PAGE_COUNT > 1; with a single-page
 * mailbox the call collapses to the existing `succeeds` test.
 */
#if RXTX_MAX_PAGE_COUNT > 1
TEST(ffa_rxtx_map, succeeds_with_max_page_count)
{
	EXPECT_EQ(ffa_rxtx_map_pages((hf_ipaddr_t)send_pages_max,
				     (hf_ipaddr_t)recv_pages_max,
				     FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT)
			  .func,
		  FFA_SUCCESS_32);
}
#endif /* RXTX_MAX_PAGE_COUNT > 1 */

/**
 * RXTX_MAP fails when page_count is zero.
 */
TEST(ffa_rxtx_map, fails_with_zero_page_count)
{
	EXPECT_FFA_ERROR(ffa_rxtx_map_pages(send_page_addr, recv_page_addr, 0),
			 FFA_INVALID_PARAMETERS);
}

/**
 * RXTX_MAP fails when page_count exceeds the maximum.
 */
TEST(ffa_rxtx_map, fails_with_page_count_exceeding_max)
{
	EXPECT_FFA_ERROR(
		ffa_rxtx_map_pages((hf_ipaddr_t)send_pages_max,
				   (hf_ipaddr_t)recv_pages_max,
				   FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT + 1),
		FFA_INVALID_PARAMETERS);
}

/**
 * Multi-page send and receive buffers must not overlap.
 *
 * Only meaningful when RXTX_MAX_PAGE_COUNT > 1: with a single-page
 * mailbox the two ranges below land on different pages and there is
 * no overlap to detect.
 */
#if RXTX_MAX_PAGE_COUNT > 1
TEST(ffa_rxtx_map, fails_with_overlapping_multi_page_buffers)
{
	/* recv starts 2 pages into send buffer, causing overlap. */
	EXPECT_FFA_ERROR(ffa_rxtx_map_pages((hf_ipaddr_t)send_pages_max,
					    (hf_ipaddr_t)send_pages_max +
						    FFA_PAGE_SIZE * 2,
					    FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT),
			 FFA_INVALID_PARAMETERS);
}
#endif /* RXTX_MAX_PAGE_COUNT > 1 */

/**
 * Unmap and remap with a different page count succeeds.
 *
 * Only meaningful when RXTX_MAX_PAGE_COUNT > 1; with a single-page
 * mailbox both the initial and remap calls request a single page and
 * the test reduces to the existing `succeeds_in_remapping_region`.
 */
#if RXTX_MAX_PAGE_COUNT > 1
TEST(ffa_rxtx_unmap, succeeds_remap_with_different_page_count)
{
	/* Map with single page. */
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);

	/* Remap with max pages. */
	EXPECT_EQ(ffa_rxtx_map_pages((hf_ipaddr_t)send_pages_max,
				     (hf_ipaddr_t)recv_pages_max,
				     FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT)
			  .func,
		  FFA_SUCCESS_32);
}
#endif /* RXTX_MAX_PAGE_COUNT > 1 */

/*
 * Skip the data-path tests below in the default single-page build: the
 * shared mailbox fixture (used by other tests in this binary) is only one
 * page, so registering a multi-page mailbox here would leave the rest of
 * the test suite without a usable mailbox. Everything below is meaningful
 * only when RXTX_MAX_PAGE_COUNT > 1, e.g. the qemu_aarch64_vhe_rxtx16k
 * variant.
 */
#if RXTX_MAX_PAGE_COUNT > 1

/**
 * Multi-page partition_info_get exercises cpu_message_buffer staging.
 *
 * With RXTX_MAX_PAGE_COUNT > 1 the SPMC's per-CPU staging
 * buffer is several pages large; the SPMC copies partition descriptors
 * into staging and then into the caller's RX buffer. This test:
 *
 * 1. Pre-paints the entire multi-page RX buffer with a sentinel.
 * 2. Calls partition_info_get against the multi-page mailbox.
 * 3. Verifies the descriptor data is correct at the start of RX.
 * 4. Verifies that bytes past the actual descriptor table are zero —
 *    i.e. the producer cleared the unpopulated tail of the RX buffer and
 *    did not leak stale staging-buffer contents into the caller's RX area.
 *
 * Step 4 validates the FF-A v1.3 section 4.10 requirement that a producer
 * (here the SPMC, a higher-EL producer to a lower-EL consumer) clears the
 * unpopulated contents of the buffer it hands to the consumer.
 */
TEST(ffa_rxtx_data_path, partition_info_get_multi_page_no_overcopy)
{
	const uint8_t sentinel = 0xA5;
	const size_t recv_size =
		FFA_PAGE_SIZE * FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT;
	struct ffa_value ret;
	struct ffa_uuid uuid;
	uint32_t partition_count;
	size_t descriptor_bytes;
	const struct ffa_partition_info *partitions;

	/*
	 * Pin the FF-A version so the count returned by the count-only
	 * call matches the count returned by the descriptor-fetching call
	 * (the v1.0 descriptor shape collapses multi-UUID partitions to
	 * one entry, which would otherwise mismatch).
	 */
	EXPECT_EQ(ffa_version(FFA_VERSION_1_2), FFA_VERSION_COMPILED);

	memset_s(recv_pages_max, recv_size, sentinel, recv_size);

	EXPECT_EQ(ffa_rxtx_map_pages((hf_ipaddr_t)send_pages_max,
				     (hf_ipaddr_t)recv_pages_max,
				     FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT)
			  .func,
		  FFA_SUCCESS_32);

	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	partition_count = ret.arg2;
	ASSERT_GT(partition_count, 0);

	ret = ffa_partition_info_get(&uuid, 0);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg2, partition_count);

	partitions = (const struct ffa_partition_info *)recv_pages_max;
	for (uint32_t i = 0; i < partition_count; i++) {
		EXPECT_NE(partitions[i].vm_id, 0);
		EXPECT_GT(partitions[i].vcpu_count, 0);
	}

	/*
	 * Anything past the descriptor table must be zero, not the sentinel:
	 * the producer (SPMC) must clear the unpopulated tail of the RX buffer
	 * so it cannot leak stale staging-buffer contents to the consumer
	 * (FF-A v1.3 section 4.10). `ret.arg3` is the size of one descriptor.
	 */
	descriptor_bytes = (size_t)partition_count * (size_t)ret.arg3;
	ASSERT_LE(descriptor_bytes, recv_size);
	for (size_t i = descriptor_bytes; i < recv_size; i++) {
		EXPECT_EQ(recv_pages_max[i], 0);
	}

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
}

#endif /* RXTX_MAX_PAGE_COUNT > 1 */

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
