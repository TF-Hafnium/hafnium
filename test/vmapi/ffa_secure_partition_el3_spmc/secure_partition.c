/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/mm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "../msr.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
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

	ret = ffa_features(FFA_MEM_RELINQUISH_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_FRAG_TX_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_YIELD_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_SECONDARY_EP_REGISTER_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_PERM_GET_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MEM_PERM_SET_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MEM_PERM_GET_64);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MEM_PERM_SET_64);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);
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
 * The configured send/receive addresses can't be unaligned.
 */
TEST(ffa_rxtx_map, fails_with_unaligned_pointer)
{
	uint8_t maybe_aligned[2];
	hf_ipaddr_t unaligned_addr = (hf_ipaddr_t)&maybe_aligned[1];
	hf_ipaddr_t aligned_addr = (hf_ipaddr_t)send_page;

	/* Check that the address is unaligned. */
	ASSERT_FALSE(is_aligned(unaligned_addr, 2));

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
 * The buffer pair can be successfully unmapped from a SP that has
 * just created the mapping.
 */
TEST(ffa_rxtx_unmap, succeeds)
{
	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	EXPECT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
}

/**
 * Unmap will fail if no mapping exists for the SP.
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
 * Currently sending a direct message request from the SWd to the NWd is not
 * supported; check that if this attempted an FFA_ERROR with the
 * FFA_INVALID_PARAMETERS error code is returned.
 */
TEST(ffa_msg_send_direct_req, fails_if_sp_to_nwd)
{
	const uint32_t msg[] = {0x00001111, 0x22223333, 0x44445555, 0x66667777,
				0x88889999};
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_msg_send_direct_req(own_id, HF_HYPERVISOR_VM_ID + 1, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Dumps the content of the SP's boot information. The fact it can dump this
 * info serves as validator that the SP can access the information.
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

	HFTEST_LOG("FF-A Manifest Address: %lx", fdt_info->content);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	fdt_ptr = (void*)fdt_info->content;

	ASSERT_TRUE(fdt_size_from_header(fdt_ptr, &fdt_len));
	ASSERT_TRUE(fdt_init_from_ptr(&fdt, fdt_ptr, fdt_len));
	EXPECT_TRUE(fdt_find_node(&fdt, "/", &root));

	EXPECT_TRUE(fdt_is_compatible(&root, "arm,ffa-manifest-1.0"));
	EXPECT_TRUE(fdt_read_number(&root, "ffa-version", &ffa_version));
	HFTEST_LOG("FF-A Version: %lx", ffa_version);
	ASSERT_EQ(ffa_version, FFA_VERSION_COMPILED);
}

/**
 * Validate a SP is not meant to use the FFA_NOTIFICATION_INFO_GET interface.
 */
TEST(ffa_notifications, fails_info_get_from_sp)
{
	EXPECT_FFA_ERROR(ffa_notification_info_get(), FFA_NOT_SUPPORTED);
}

/**
 * Validate FFA_CONSOLE_LOG sends a message.
 */
TEST(ffa_console_log, successfull_msg_send)
{
	const char msg_long[] = "This does not fit in 6x32 bits, only 6x64\n";
	const char msg_short[] = "This fits in 6x32 bits\n";

	EXPECT_EQ(ffa_console_log_32(msg_short, sizeof(msg_short)).func,
		  FFA_SUCCESS_32);

	EXPECT_EQ(ffa_console_log_64(msg_long, sizeof(msg_long)).func,
		  FFA_SUCCESS_32);
}

/**
 * Validate FFA_CONSOLE_LOG reports invalid parameters on inadequate message.
 */
TEST(ffa_console_log, invalid_parameters)
{
	/* Expecting INVALID_PARAMETERS on zero-length message */
	struct ffa_value req = {
		.func = FFA_CONSOLE_LOG_64,
		.arg1 = 0,
	};
	EXPECT_FFA_ERROR(ffa_call(req), FFA_INVALID_PARAMETERS);

	/* Expecting INVALID_PARAMETERS on length > payload message */
	req.arg1 = 0xffff;
	EXPECT_FFA_ERROR(ffa_call(req), FFA_INVALID_PARAMETERS);
}

/**
 * Validate a S-EL1 partition can enable/disable alignment checks.
 */
TEST(arch_features, vm_unaligned_access)
{
	uint64_t sctlr_el1;
	uint64_t val = 0x1122334400000000;
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	volatile uint32_t* ptr = (volatile uint32_t*)((uintptr_t)&val + 2);

	exception_setup(NULL, exception_handler_skip_instruction);

	/* Expect alignment checks to be disabled. */
	sctlr_el1 = read_msr(sctlr_el1);
	EXPECT_EQ((sctlr_el1 >> 1) & 1, 0);

	/* This read access is expected to pass. */
	EXPECT_EQ(*ptr, 0x33440000);
	EXPECT_EQ(exception_handler_get_num(), 0);

	/* Enable alignment checks. */
	write_msr(sctlr_el1, sctlr_el1 | 2);
	isb();

	/* This read access is expected to trigger an abort. */
	*ptr;

	EXPECT_EQ(exception_handler_get_num(), 1);
}
