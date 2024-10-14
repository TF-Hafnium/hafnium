/*
 * Copyright 2021 The Hafnium Authors.
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
// NOLINTNEXTLINE(readability-function-size)
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

	ret = ffa_features_with_input_property(
		FFA_MEM_RETRIEVE_REQ_32,
		FFA_FEATURES_MEM_RETRIEVE_REQ_NS_SUPPORT);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg1, 0);
	EXPECT_EQ(ret.arg2,
		  FFA_FEATURES_MEM_RETRIEVE_REQ_BUFFER_SUPPORT |
			  FFA_FEATURES_MEM_RETRIEVE_REQ_NS_SUPPORT |
			  FFA_FEATURES_MEM_RETRIEVE_REQ_HYPERVISOR_SUPPORT);

	ret = ffa_features(FFA_MEM_RETRIEVE_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RELINQUISH_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RECLAIM_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_FRAG_TX_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_FRAG_RX_32);
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
}

static bool v1_1_or_later(void)
{
	return FFA_VERSION_COMPILED >= FFA_VERSION_1_1;
}

static bool v1_2_or_later(void)
{
	return FFA_VERSION_COMPILED >= FFA_VERSION_1_2;
}

TEST_PRECONDITION(ffa_features, succeeds_ffa_call_ids_v1_1, v1_1_or_later)
{
	struct ffa_value ret;

	ret = ffa_features(FFA_MEM_PERM_GET_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MEM_PERM_SET_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MEM_PERM_GET_64);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MEM_PERM_SET_64);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_SEND2_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

TEST_PRECONDITION(ffa_features, succeeds_ffa_call_ids_v1_2, v1_2_or_later)
{
	struct ffa_value ret;
	struct ffa_features_rxtx_map_params rxtx_map_params;

	ret = ffa_features(FFA_CONSOLE_LOG_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_CONSOLE_LOG_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_PARTITION_INFO_GET_REGS_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ2_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP2_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RXTX_MAP_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	rxtx_map_params = ffa_features_rxtx_map_params(ret);
	EXPECT_EQ((uint8_t)rxtx_map_params.min_buf_size,
		  FFA_RXTX_MAP_MIN_BUF_4K);
	EXPECT_EQ((uint16_t)rxtx_map_params.mbz, 0);
	EXPECT_EQ((uint16_t)rxtx_map_params.max_buf_size,
		  FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT);
}

/** Validates return for FFA_FEATURES provided a valid feature ID. */
TEST(ffa_features, succeeds_feature_ids)
{
	struct ffa_value ret = ffa_features(FFA_FEATURE_NPI);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_feature_intid(ret), HF_NOTIFICATION_PENDING_INTID);

	ret = ffa_features(FFA_FEATURE_SRI);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

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
 * Validates error return for FFA_FEATURES given:
 *  - Version is v1.1 or greater
 *  - function_id is FFA_MEM_RETRIEVE_REQ_32
 *  - parameter does not have bit 1 set
 */
TEST(ffa_features, fails_if_parameter_wrong_and_v_1_1)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_1), FFA_VERSION_COMPILED);

	EXPECT_FFA_ERROR(
		ffa_features_with_input_property(FFA_MEM_RETRIEVE_REQ_32, 0),
		FFA_NOT_SUPPORTED);
}

TEST(ffa_features, does_not_fail_if_parameter_wrong_and_v_1_0)
{
	struct ffa_value ret;

	EXPECT_EQ(ffa_version(FFA_VERSION_1_0), FFA_VERSION_COMPILED);

	ret = ffa_features_with_input_property(FFA_MEM_RETRIEVE_REQ_32, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
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
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

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
	ffa_id_t own_id = hf_vm_get_id();

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

	HFTEST_LOG("FF-A Manifest Address: %lx", fdt_info->content);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	fdt_ptr = (void*)fdt_info->content;

	ASSERT_TRUE(fdt_size_from_header(fdt_ptr, &fdt_len));
	ASSERT_TRUE(fdt_init_from_ptr(&fdt, fdt_ptr, fdt_len));
	EXPECT_TRUE(fdt_find_node(&fdt, "/", &root));

	EXPECT_TRUE(fdt_is_compatible(&root, "arm,ffa-manifest-1.0"));
	EXPECT_TRUE(fdt_read_number(&root, "ffa-version", &ffa_version));
	HFTEST_LOG("FF-A Version: %lx", ffa_version);
	ASSERT_EQ(ffa_version, FFA_VERSION_1_2);
}

/*
 * Validate a SP is not meant to use the FFA_NOTIFICATION_INFO_GET interface.
 */
TEST(ffa_notifications, fails_info_get_from_sp)
{
	EXPECT_FFA_ERROR(ffa_notification_info_get(), FFA_NOT_SUPPORTED);
}

/*
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

/*
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
 * Validate FFA_CONSOLE_LOG sends a message.
 */
TEST(ffa_console_log_extended_reg, successfull_msg_send)
{
	/* This does not fit in 16x32 bits, only 16x64 */
	char msg_long[] =
		"aaaaaaaaaaaaaa16"
		"aaaaaaaaaaaaaa32"
		"aaaaaaaaaaaaaa48"
		"aaaaaaaaaaaaaa64"
		"aaaaaaaaaaaaaa80"
		"aaaaaaaaaaaaaa96"
		"aaaaaaaaaaaaa112"
		"aaaaaaaaaaaa127"; /* plus 1 for the trailing '\0' */

	static_assert(sizeof(msg_long) == 128,
		      "msg_long should be 128 bytes long");

	EXPECT_EQ(ffa_console_log_64_extended(msg_long, sizeof(msg_long)).func,
		  FFA_SUCCESS_32);
}

/**
 * Validate FFA_CONSOLE_LOG reports invalid parameters on inadequate message.
 */
TEST(ffa_console_log_extended_reg, invalid_parameters)
{
	/* Expecting INVALID_PARAMETERS on zero-length message */
	EXPECT_FFA_ERROR(ffa_console_log_64_extended("abc", 0),
			 FFA_INVALID_PARAMETERS);
	EXPECT_FFA_ERROR(ffa_console_log_64_extended("abc", 16 * 8 + 1),
			 FFA_INVALID_PARAMETERS);
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

/*
 * Validate PAuth can be enabled at S-EL1 and an S-EL1 partition can
 * change its APIAKey.
 */
TEST(arch_features, enable_pauth)
{
	uint64_t sctlr_el1;
	uint64_t id_aa64isar1_el1;
	uint64_t sctlr_el1_enia = (UINT64_C(0x1) << 31);
	uint64_t apiakeylo_el1_val = (0x123456789);
	uint64_t apiakeyhi_el1_val = (0x987654321);

	/* Check that PAuth is implemented. */
	id_aa64isar1_el1 = read_msr(id_aa64isar1_el1);
	EXPECT_NE((id_aa64isar1_el1 & (0xff0)), 0);

	/* Check that PAuth is enabled at EL1. */
	sctlr_el1 = read_msr(sctlr_el1);
	EXPECT_EQ((sctlr_el1 & sctlr_el1_enia), sctlr_el1_enia);

	/* Attempt to write to APIAKey_EL1) */
	write_msr(s3_0_c2_c1_0, apiakeylo_el1_val);
	write_msr(s3_0_c2_c1_1, apiakeyhi_el1_val);
	isb();

	/* Verify keys were written to. */
	EXPECT_EQ(read_msr(s3_0_c2_c1_0), apiakeylo_el1_val);
	EXPECT_EQ(read_msr(s3_0_c2_c1_1), apiakeyhi_el1_val);

	/* Restore APIA keys to inital value. */
	write_msr(s3_0_c2_c1_0, 1842);
	write_msr(s3_0_c2_c1_1, 1842);
	isb();
}

static void pauth_fault_helper(void)
{
	FAIL("This should not be called\n");
}

/**
 * Trigger a Pointer Authentication Fault and verify that an exception
 * was generated.
 *
 * Note that the fault does not occur on the AUTIASP instruction but on the
 * RET instruction. The AUTIASP instruction adds a PAC to the LR. Since the LR
 * has been corrupted, the PAC will be faulty and the resulting value of LR will
 * be an invalid VA causing the RET instruction to result in a translation
 * fault.
 *
 * A PAC authentication instruction directly generating a PAC Fail exception
 * requires implementation of FEAT_FPAC or FEAT_FPACCOMBINE.
 *
 * For more information, see section D8.10.4 `Faulting on pointer
 * authentication`of ARM ARM DDI0487K.
 */
TEST(arch_features, pauth_fault)
{
	uintptr_t bad_addr = (uintptr_t)&pauth_fault_helper;
	uint64_t exception_return_addr;

	exception_setup(NULL, exception_handler_skip_to_instruction);

	__asm__("adr %0, end; " : "=r"(exception_return_addr) :);

	exception_handler_set_return_addr(exception_return_addr);

	/* Overwrite LR and trigger PAuth Fault exception. */
	__asm__("mov x17, x30; "
		"mov x30, %0; "	      /* Overwite LR. */
		"add sp, sp, #0x30; " /* Revert SP to value at entrance to
					 function (when PAC is generated). */
		"isb; "
		"autiasp; "
		"sub sp, sp, #0x30; " /* Restore SP. */
		"ret; "		      /* Fault on return.  */
		"end: "
		:
		: "r"(bad_addr));

	EXPECT_EQ(exception_handler_get_num(), 1);
}

static struct ffa_value test_ffa_smc(uint32_t func, uint64_t arg0,
				     uint64_t arg1, uint64_t arg2,
				     uint64_t arg3, uint64_t arg4,
				     uint64_t arg5, uint64_t arg6)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = arg3;
	register uint64_t r5 __asm__("x5") = arg4;
	register uint64_t r6 __asm__("x6") = arg5;
	register uint64_t r7 __asm__("x7") = arg6;
	register uint64_t r8 __asm__("x8") = 0xa8;
	register uint64_t r9 __asm__("x9") = 0xa9;
	register uint64_t r10 __asm__("x10") = 0xa10;
	register uint64_t r11 __asm__("x11") = 0xa11;
	register uint64_t r12 __asm__("x12") = 0xa12;
	register uint64_t r13 __asm__("x13") = 0xa13;
	register uint64_t r14 __asm__("x14") = 0xa14;
	register uint64_t r15 __asm__("x15") = 0xa15;
	register uint64_t r16 __asm__("x16") = 0xa16;
	register uint64_t r17 __asm__("x17") = 0xa17;
	register uint64_t r18 __asm__("x18") = 0xa18;
	register uint64_t r19 __asm__("x19") = 0xa19;
	register uint64_t r20 __asm__("x20") = 0xa20;
	register uint64_t r21 __asm__("x21") = 0xa21;
	register uint64_t r22 __asm__("x22") = 0xa22;
	register uint64_t r23 __asm__("x23") = 0xa23;
	register uint64_t r24 __asm__("x24") = 0xa24;
	register uint64_t r25 __asm__("x25") = 0xa25;
	register uint64_t r26 __asm__("x26") = 0xa26;
	register uint64_t r27 __asm__("x27") = 0xa27;
	register uint64_t r28 __asm__("x28") = 0xa28;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		"+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(r16),
		"+r"(r17), "+r"(r18), "+r"(r19), "+r"(r20), "+r"(r21),
		"+r"(r22), "+r"(r23), "+r"(r24), "+r"(r25), "+r"(r26),
		"+r"(r27), "+r"(r28));

	EXPECT_EQ(r8, 0xa8);
	EXPECT_EQ(r9, 0xa9);
	EXPECT_EQ(r10, 0xa10);
	EXPECT_EQ(r11, 0xa11);
	EXPECT_EQ(r12, 0xa12);
	EXPECT_EQ(r13, 0xa13);
	EXPECT_EQ(r14, 0xa14);
	EXPECT_EQ(r15, 0xa15);
	EXPECT_EQ(r16, 0xa16);
	EXPECT_EQ(r17, 0xa17);
	EXPECT_EQ(r18, 0xa18);
	EXPECT_EQ(r19, 0xa19);
	EXPECT_EQ(r20, 0xa20);
	EXPECT_EQ(r21, 0xa21);
	EXPECT_EQ(r22, 0xa22);
	EXPECT_EQ(r23, 0xa23);
	EXPECT_EQ(r24, 0xa24);
	EXPECT_EQ(r25, 0xa25);
	EXPECT_EQ(r26, 0xa26);
	EXPECT_EQ(r27, 0xa27);
	EXPECT_EQ(r28, 0xa28);

	return (struct ffa_value){.func = r0,
				  .arg1 = r1,
				  .arg2 = r2,
				  .arg3 = r3,
				  .arg4 = r4,
				  .arg5 = r5,
				  .arg6 = r6,
				  .arg7 = r7};
}

/**
 * An FF-A service call is emitted at the secure virtual FF-A instance.
 * The service does not require results in registers beyond x7, hence per
 * SMCCCv1.2 ensure GP registers beyond x7 are preserved by callee.
 */
TEST(arch, smccc_regs_callee_preserved)
{
	struct ffa_value ret;

	ret = test_ffa_smc(FFA_VERSION_32, 0x10001, 0, 0, 0, 0, 0, 0);
	EXPECT_GE(ret.func, 0x10001);
	EXPECT_EQ(ret.arg1, 0x0);
	EXPECT_EQ(ret.arg2, 0x0);
	EXPECT_EQ(ret.arg3, 0x0);
	EXPECT_EQ(ret.arg4, 0x0);
	EXPECT_EQ(ret.arg5, 0x0);
	EXPECT_EQ(ret.arg6, 0x0);
	EXPECT_EQ(ret.arg7, 0x0);

	ret = test_ffa_smc(FFA_ID_GET_32, 0, 0, 0, 0, 0, 0, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg1, 0x0);
	/* In this setup a single partition exists whose ID is 0x8001. */
	EXPECT_EQ(ret.arg2, 0x8001);
	EXPECT_EQ(ret.arg3, 0x0);
	EXPECT_EQ(ret.arg4, 0x0);
	EXPECT_EQ(ret.arg5, 0x0);
	EXPECT_EQ(ret.arg6, 0x0);
	EXPECT_EQ(ret.arg7, 0x0);
}

static struct ffa_value test_ffa_smc_ext(uint32_t func, uint64_t arg0,
					 uint64_t arg1, uint64_t arg2,
					 uint64_t arg3, uint64_t arg4,
					 uint64_t arg5, uint64_t arg6)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = arg3;
	register uint64_t r5 __asm__("x5") = arg4;
	register uint64_t r6 __asm__("x6") = arg5;
	register uint64_t r7 __asm__("x7") = arg6;
	register uint64_t r8 __asm__("x8") = 0xa8;
	register uint64_t r9 __asm__("x9") = 0xa9;
	register uint64_t r10 __asm__("x10") = 0xa10;
	register uint64_t r11 __asm__("x11") = 0xa11;
	register uint64_t r12 __asm__("x12") = 0xa12;
	register uint64_t r13 __asm__("x13") = 0xa13;
	register uint64_t r14 __asm__("x14") = 0xa14;
	register uint64_t r15 __asm__("x15") = 0xa15;
	register uint64_t r16 __asm__("x16") = 0xa16;
	register uint64_t r17 __asm__("x17") = 0xa17;
	register uint64_t r18 __asm__("x18") = 0xa18;
	register uint64_t r19 __asm__("x19") = 0xa19;
	register uint64_t r20 __asm__("x20") = 0xa20;
	register uint64_t r21 __asm__("x21") = 0xa21;
	register uint64_t r22 __asm__("x22") = 0xa22;
	register uint64_t r23 __asm__("x23") = 0xa23;
	register uint64_t r24 __asm__("x24") = 0xa24;
	register uint64_t r25 __asm__("x25") = 0xa25;
	register uint64_t r26 __asm__("x26") = 0xa26;
	register uint64_t r27 __asm__("x27") = 0xa27;
	register uint64_t r28 __asm__("x28") = 0xa28;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		"+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(r16),
		"+r"(r17), "+r"(r18), "+r"(r19), "+r"(r20), "+r"(r21),
		"+r"(r22), "+r"(r23), "+r"(r24), "+r"(r25), "+r"(r26),
		"+r"(r27), "+r"(r28));

	EXPECT_EQ(r18, 0xa18);
	EXPECT_EQ(r19, 0xa19);
	EXPECT_EQ(r20, 0xa20);
	EXPECT_EQ(r21, 0xa21);
	EXPECT_EQ(r22, 0xa22);
	EXPECT_EQ(r23, 0xa23);
	EXPECT_EQ(r24, 0xa24);
	EXPECT_EQ(r25, 0xa25);
	EXPECT_EQ(r26, 0xa26);
	EXPECT_EQ(r27, 0xa27);
	EXPECT_EQ(r28, 0xa28);

	return (struct ffa_value){
		.func = r0,
		.arg1 = r1,
		.arg2 = r2,
		.arg3 = r3,
		.arg4 = r4,
		.arg5 = r5,
		.arg6 = r6,
		.arg7 = r7,
		.extended_val.arg8 = r8,
		.extended_val.arg9 = r9,
		.extended_val.arg10 = r10,
		.extended_val.arg11 = r11,
		.extended_val.arg12 = r12,
		.extended_val.arg13 = r13,
		.extended_val.arg14 = r14,
		.extended_val.arg15 = r15,
		.extended_val.arg16 = r16,
		.extended_val.arg17 = r17,
		.extended_val.valid = 1,
	};
}

/**
 * An FF-A service call is emitted at the secure virtual FF-A instance.
 * The service holds results in x0-x17 GP regs. Per SMCCCv1.2 ensure
 * registers beyond x17 are preserved by callee.
 */
TEST(arch, smccc_extended_regs_callee_preserved)
{
	struct ffa_value ret;

	ret = test_ffa_smc_ext(FFA_PARTITION_INFO_GET_REGS_64, 0, 0, 0, 0, 0, 0,
			       0);
	EXPECT_GE(ret.func, FFA_SUCCESS_64);
	EXPECT_TRUE(ret.extended_val.valid);
	EXPECT_EQ(ret.arg1, 0x0);
	EXPECT_EQ(ffa_partition_info_regs_get_desc_size(ret),
		  (uint16_t)sizeof(struct ffa_partition_info));
}

static struct ffa_value test_smc_forward(uint32_t func, uint64_t arg0,
					 uint64_t arg1, uint64_t arg2)
{
	register uint64_t r0 __asm__("x0") = func;
	register uint64_t r1 __asm__("x1") = arg0;
	register uint64_t r2 __asm__("x2") = arg1;
	register uint64_t r3 __asm__("x3") = arg2;
	register uint64_t r4 __asm__("x4") = 0xa4;
	register uint64_t r5 __asm__("x5") = 0xa5;
	register uint64_t r6 __asm__("x6") = 0xa6;
	register uint64_t r7 __asm__("x7") = 0xa7;
	register uint64_t r8 __asm__("x8") = 0xa8;
	register uint64_t r9 __asm__("x9") = 0xa9;
	register uint64_t r10 __asm__("x10") = 0xa10;
	register uint64_t r11 __asm__("x11") = 0xa11;
	register uint64_t r12 __asm__("x12") = 0xa12;
	register uint64_t r13 __asm__("x13") = 0xa13;
	register uint64_t r14 __asm__("x14") = 0xa14;
	register uint64_t r15 __asm__("x15") = 0xa15;
	register uint64_t r16 __asm__("x16") = 0xa16;
	register uint64_t r17 __asm__("x17") = 0xa17;
	register uint64_t r18 __asm__("x18") = 0xa18;
	register uint64_t r19 __asm__("x19") = 0xa19;
	register uint64_t r20 __asm__("x20") = 0xa20;
	register uint64_t r21 __asm__("x21") = 0xa21;
	register uint64_t r22 __asm__("x22") = 0xa22;
	register uint64_t r23 __asm__("x23") = 0xa23;
	register uint64_t r24 __asm__("x24") = 0xa24;
	register uint64_t r25 __asm__("x25") = 0xa25;
	register uint64_t r26 __asm__("x26") = 0xa26;
	register uint64_t r27 __asm__("x27") = 0xa27;
	register uint64_t r28 __asm__("x28") = 0xa28;

	__asm__ volatile(
		"smc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5),
		"+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		"+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15), "+r"(r16),
		"+r"(r17), "+r"(r18), "+r"(r19), "+r"(r20), "+r"(r21),
		"+r"(r22), "+r"(r23), "+r"(r24), "+r"(r25), "+r"(r26),
		"+r"(r27), "+r"(r28));

	EXPECT_EQ(r4, 0xa4);
	EXPECT_EQ(r5, 0xa5);
	EXPECT_EQ(r6, 0xa6);
	EXPECT_EQ(r7, 0xa7);
	EXPECT_EQ(r8, 0xa8);
	EXPECT_EQ(r9, 0xa9);
	EXPECT_EQ(r10, 0xa10);
	EXPECT_EQ(r11, 0xa11);
	EXPECT_EQ(r12, 0xa12);
	EXPECT_EQ(r13, 0xa13);
	EXPECT_EQ(r14, 0xa14);
	EXPECT_EQ(r15, 0xa15);
	EXPECT_EQ(r16, 0xa16);
	EXPECT_EQ(r17, 0xa17);
	EXPECT_EQ(r18, 0xa18);
	EXPECT_EQ(r19, 0xa19);
	EXPECT_EQ(r20, 0xa20);
	EXPECT_EQ(r21, 0xa21);
	EXPECT_EQ(r22, 0xa22);
	EXPECT_EQ(r23, 0xa23);
	EXPECT_EQ(r24, 0xa24);
	EXPECT_EQ(r25, 0xa25);
	EXPECT_EQ(r26, 0xa26);
	EXPECT_EQ(r27, 0xa27);
	EXPECT_EQ(r28, 0xa28);

	return (struct ffa_value){
		.func = r0,
		.arg1 = r1,
		.arg2 = r2,
		.arg3 = r3,
	};
}

/**
 * Emit an SMC call to a (non-FF-A) TF-A service passed-through Hafnium by an
 * allow list SMC id.
 */
TEST(arch, smccc_forward)
{
	const uint64_t pmf_smc_get_timestamp_32 = 0x82000010;
	struct ffa_value ret;

	/*
	 * Use PMF [1] as a TF-A service example. Omit x1, x2, x3 arguments as
	 * the intent is just a matter of reaching the service via Hafnium.
	 * The service is not using registers beyond x4 for results, hence per
	 * SMCCCv1.2 GP registers beyond ones used as results must be preserved
	 * by the callee.
	 *
	 * [1]
	 * https://trustedfirmware-a.readthedocs.io/en/latest/design/firmware-design.html#retrieving-a-timestamp
	 */
	ret = test_smc_forward(pmf_smc_get_timestamp_32, 0, 0, 0);
	EXPECT_EQ(ret.func, (unsigned long)-22);
	EXPECT_EQ(ret.arg1, 0x0);
	EXPECT_EQ(ret.arg2, 0x0);
	EXPECT_EQ(ret.arg3, 0x0);
}

TEST(ffa_enum_names, success_and_failure)
{
	EXPECT_STREQ(ffa_func_name(FFA_ERROR_32), "FFA_ERROR_32");
	EXPECT_STREQ(ffa_func_name(FFA_EL3_INTR_HANDLE_32),
		     "FFA_EL3_INTR_HANDLE_32");
	EXPECT_STREQ(ffa_func_name(0), "UNKNOWN");

	EXPECT_STREQ(ffa_error_name(FFA_NOT_SUPPORTED), "FFA_NOT_SUPPORTED");
	EXPECT_STREQ(ffa_error_name(FFA_NO_DATA), "FFA_NO_DATA");
	EXPECT_STREQ(ffa_error_name(0), "UNKNOWN");
}

/**
 * Verify that partition discovery via the FFA_PARTITION_INFO interface
 * returns the expected information on the VMs in the system, which in this
 * case is only one primary VM.
 *
 * Verify also that calls to the FFA_PARTITION_INFO interface fail when
 * expected, e.g., if the mailbox isn't setup or the RX buffer is busy.
 */
TEST(ffa, ffa_partition_info)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info* partitions;
	struct ffa_uuid uuid;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Try to get partition information before the RX buffer is setup. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	/* Only getting the partition count should succeed however. */
	ret = ffa_partition_info_get(&uuid, FFA_PARTITION_COUNT_FLAG);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ret.arg2, 1);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;

	/* Check that the expected partition information is returned. */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	/* There should only be the primary VM in this test. */
	EXPECT_EQ(ret.arg2, 1);
	EXPECT_EQ(partitions[0].vm_id, hf_vm_get_id());
	/* The primary should have at least one vCPU. */
	EXPECT_GE(partitions[0].vcpu_count, 1);

	/*
	 * Check that the partition information cannot be requested if the RX
	 * buffer is busy.
	 */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_BUSY);

	/* Release the buffer and try again. */
	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

SET_UP(ffa_v1_0)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_0), FFA_VERSION_COMPILED);
}

TEST(ffa_v1_0, ffa_partition_info_v1_0)
{
	struct mailbox_buffers mb;
	struct ffa_value ret;
	const struct ffa_partition_info* partitions;
	struct ffa_uuid uuid;

	/* A Null UUID requests information for all partitions. */
	ffa_uuid_init(0, 0, 0, 0, &uuid);

	/* Setup the mailbox (which holds the RX buffer). */
	mb = set_up_mailbox();
	partitions = mb.recv;
	/*
	 * Test the correct descriptor is returned
	 */
	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	/* There should only be the primary VM in this test. */
	EXPECT_EQ(ret.arg2, 1);
	EXPECT_EQ(partitions[0].vm_id, hf_vm_get_id());
	/* The primary should have at least one vCPU. */
	EXPECT_GE(partitions[0].vcpu_count, 1);

	ret = ffa_rx_release();
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	/* Try to get partition information for an unrecognized UUID. */
	ffa_uuid_init(0, 0, 0, 1, &uuid);

	ret = ffa_partition_info_get(&uuid, 0);
	EXPECT_FFA_ERROR(ret, FFA_INVALID_PARAMETERS);
}

/**
 * Major and minor versions match exactly, so they are compatible.
 */
TEST(ffa_version, succeeds_current_version)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED), FFA_VERSION_COMPILED);
}

/**
 * Major versions are equal, and caller's minor version is < callee's minor
 * version, so they are compatible.
 */
TEST(ffa_version, succeeds_older_compatible_version)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_1_1), FFA_VERSION_COMPILED);
}

/**
 * Highest bit must be unset.
 */
TEST(ffa_version, fails_highest_bit_set)
{
	EXPECT_EQ((enum ffa_error)ffa_version(-1), FFA_NOT_SUPPORTED);
}

/**
 * Caller's major version is < callee's major version, so they are incompatible.
 */
TEST(ffa_version, fails_major_version_too_low)
{
	EXPECT_EQ((enum ffa_error)ffa_version(make_ffa_version(0, 1)),
		  FFA_NOT_SUPPORTED);
}

/**
 * Caller's major version is > callee's major version, so they are incompatible.
 */
TEST(ffa_version, fails_major_version_too_high)
{
	EXPECT_EQ((enum ffa_error)ffa_version(make_ffa_version(2, 0)),
		  FFA_NOT_SUPPORTED);
}

/**
 * Major versions are equal, but caller's minor version is > callee's minor
 * version, so they are incompatible.
 */
TEST(ffa_version, fails_minor_version_too_high)
{
	EXPECT_EQ((enum ffa_error)ffa_version(make_ffa_version(1, 3)),
		  FFA_NOT_SUPPORTED);
}

/**
 * Version is compatible, but version has already been negotiated and other ABI
 * calls have been made, so the version cannot be changed.
 */
TEST(ffa_version, fails_change_after_other_abis_used)
{
	EXPECT_EQ(ffa_version(FFA_VERSION_COMPILED), FFA_VERSION_COMPILED);
	EXPECT_EQ(ffa_features(FFA_VERSION_32).func, FFA_SUCCESS_32);
	EXPECT_EQ((enum ffa_error)ffa_version(FFA_VERSION_1_1),
		  FFA_NOT_SUPPORTED);
}
