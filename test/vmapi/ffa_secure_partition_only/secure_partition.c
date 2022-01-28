/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
static alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];
static_assert(sizeof(send_page) == PAGE_SIZE, "Send page is not a page.");
static_assert(sizeof(recv_page) == PAGE_SIZE, "Recv page is not a page.");

static hf_ipaddr_t send_page_addr = (hf_ipaddr_t)send_page;
static hf_ipaddr_t recv_page_addr = (hf_ipaddr_t)recv_page;

/**
 * Confirms that SP has expected ID.
 */
TEST(hf_vm_get_id, secure_partition_id)
{
	EXPECT_EQ(hf_vm_get_id(), HF_VM_ID_BASE + 1);
}

/** Ensures that FFA_FEATURES is reporting the expected interfaces. */
TEST(ffa_features, succeeds_ffa_call_ids)
{
	struct ffa_value ret;

	ret = ffa_features(FFA_ERROR_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_SUCCESS_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_INTERRUPT_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_VERSION_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_FEATURES_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RX_RELEASE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RXTX_MAP_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RXTX_UNMAP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_PARTITION_INFO_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_ID_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_WAIT_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RUN_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_DONATE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_LEND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_SHARE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RETRIEVE_REQ_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RETRIEVE_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RELINQUISH_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RECLAIM_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_BITMAP_DESTROY_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_BITMAP_DESTROY_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_SET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_BIND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_UNBIND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_NOTIFICATION_INFO_GET_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

#if (MAKE_FFA_VERSION(1, 1) <= FFA_VERSION_COMPILED)
	ret = ffa_features(FFA_MEM_PERM_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_SET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_GET_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_SET_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
#endif
}

/** Validates return for FFA_FEATURES provided a valid feature ID. */
TEST(ffa_features, succeeds_feature_ids)
{
	struct ffa_value ret = ffa_features(FFA_FEATURE_NPI);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_feature_intid(ret), HF_NOTIFICATION_PENDING_INTID);

	ret = ffa_features(FFA_FEATURE_SRI);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_feature_intid(ret), HF_SCHEDULE_RECEIVER_INTID);

	ret = ffa_features(FFA_FEATURE_MEI);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_feature_intid(ret), HF_MANAGED_EXIT_INTID);
}

/** Validates error return for FFA_FEATURES provided a wrongful feature ID. */
TEST(ffa_features, fails_if_feature_id_wrong)
{
	EXPECT_FFA_ERROR(ffa_features(0x0FFFFF), FFA_NOT_SUPPORTED);
}

/**
 * Ensures that FFA_FEATURES returns not supported for a bogus FID or
 * currently non-implemented interfaces.
 */
TEST(ffa_features, fails_func_id_not_supported)
{
	struct ffa_value ret;

	ret = ffa_features(0);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_POLL_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_YIELD_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_SEND_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);
}

/**
 * Check FFA_SPM_ID_GET can be called at secure virtual FF-A instance.
 */
TEST(ffa, ffa_spm_id_get)
{
	struct ffa_value ret = ffa_spm_id_get();

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg2, HF_SPMC_VM_ID);
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
 * A SP cannot resume a normal world VM with FFA_RUN.
 */
TEST(ffa_run, fails_to_resume_hypervisor)
{
	EXPECT_FFA_ERROR(ffa_run(HF_HYPERVISOR_VM_ID, 0), FFA_DENIED);
}

/**
 * Currently sending a direct message request from the SWd to the NWd is not
 * supported check that if this attempted an FFA_ERROR with the
 * FFA_INVALID_PARAMETERS error code is returned.
 */
TEST(ffa_msg_send_direct_req, fails_if_sp_to_nwd)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();

	res = ffa_msg_send_direct_req(own_id, HF_HYPERVISOR_VM_ID + 1, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Dumps the content of the SPs boot information. The fact it can dump this info
 * serves as validator that the SP can access the information.
 */
TEST(ffa_boot_info, dump_and_validate_boot_info)
{
	struct ffa_boot_info_header* boot_info_header = get_boot_info_header();
	struct ffa_boot_info_desc* fdt_info;

	dump_boot_info(boot_info_header);

	fdt_info = get_boot_info_desc(boot_info_header, FFA_BOOT_INFO_TYPE_STD,
				      FFA_BOOT_INFO_TYPE_ID_FDT);
	ASSERT_TRUE(fdt_info != NULL);

	EXPECT_EQ(ffa_boot_info_content_format(fdt_info),
		  FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR);
}

/**
 * Validate that SP can access its own FF-A manifest.
 */
TEST(ffa_boot_info, parse_fdt)
{
	struct ffa_boot_info_header* boot_info_header = get_boot_info_header();
	struct ffa_boot_info_desc* fdt_info;
	struct fdt fdt;
	struct fdt_node root;
	void* fdt_ptr;
	size_t fdt_len;
	uint64_t ffa_version;

	fdt_info = get_boot_info_desc(boot_info_header, FFA_BOOT_INFO_TYPE_STD,
				      FFA_BOOT_INFO_TYPE_ID_FDT);

	ASSERT_TRUE(fdt_info != NULL);

	HFTEST_LOG("FF-A Manifest Address: %x", fdt_info->content);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	fdt_ptr = (void*)fdt_info->content;

	ASSERT_TRUE(fdt_size_from_header(fdt_ptr, &fdt_len));
	ASSERT_TRUE(fdt_init_from_ptr(&fdt, fdt_ptr, fdt_len));
	EXPECT_TRUE(fdt_find_node(&fdt, "/", &root));

	EXPECT_TRUE(fdt_is_compatible(&root, "arm,ffa-manifest-1.0"));
	EXPECT_TRUE(fdt_read_number(&root, "ffa-version", &ffa_version));
	HFTEST_LOG("FF-A Version: %x", ffa_version);
	ASSERT_EQ(ffa_version, MAKE_FFA_VERSION(1, 1));
}
