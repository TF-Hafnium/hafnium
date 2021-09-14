/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"
/*
 * This must match the size specified for services1 in
 * //test/vmapi/el0_partitions/manifest.dts.
 */
#define SECONDARY_MEMORY_SIZE 1048576

extern uint8_t volatile text_begin[];
extern uint8_t volatile text_end[];
extern uint8_t volatile rodata_begin[];
extern uint8_t volatile rodata_end[];
extern uint8_t volatile data_begin[];
extern uint8_t volatile data_end[];
extern uint8_t volatile image_end[];

TEST_SERVICE(boot_memory)
{
	uint8_t checksum = 0;

	/* Check that the size passed in by Hafnium is what is expected. */
	ASSERT_EQ(SERVICE_MEMORY_SIZE(), SECONDARY_MEMORY_SIZE);

	/*
	 * Check that we can read all memory up to the given size. Calculate a
	 * basic checksum and check that it is non-zero, as a double-check that
	 * we are actually reading something.
	 */
	for (size_t i = 0; i < SERVICE_MEMORY_SIZE(); ++i) {
		checksum += text_begin[i];
	}
	ASSERT_NE(checksum, 0);
	dlog("Checksum of all memory is %d\n", checksum);

	ffa_yield();
}

TEST_SERVICE(boot_memory_underrun)
{
	/*
	 * Try to read memory below the start of the image. This should result
	 * in the VM trapping and yielding.
	 */
	dlog("Read memory below limit: %d\n", text_begin[-1]);
	dlog("Managed to read memory below limit");
	ffa_yield();
}

TEST_SERVICE(boot_memory_overrun)
{
	/*
	 * Try to read memory above the limit defined by memory_size. This
	 * should result in the VM trapping and yielding.
	 */
	dlog("Read memory above limit: %d\n",
	     text_begin[SERVICE_MEMORY_SIZE()]);
	dlog("Managed to read memory above limit");
	ffa_yield();
}

TEST_SERVICE(ffa_mem_perm_get)
{
	struct ffa_value ret = ffa_msg_wait();
	uint64_t num_pages = 0;
	uint64_t base_va = 0;
	/* Hafnium may use rx/tx buffers so one page may be marked as RO */
	uint32_t num_ro_pages_in_data = 0;

	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);

	num_pages = align_up((text_end - text_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(text_begin, PAGE_SIZE);

	while (num_pages) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RX);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	num_pages =
		align_up((rodata_end - rodata_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(rodata_begin, PAGE_SIZE);

	while (num_pages) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RO);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	num_pages = align_up((data_end - data_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);

	while (num_pages) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		if (res.arg2 == FFA_MEM_PERM_RO) {
			/*
			 * Hafnium may use rx/tx buffers so one page may be
			 * marked as RO
			 */
			num_ro_pages_in_data++;
		} else {
			EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);
		}
		base_va += PAGE_SIZE;
		num_pages--;
	}
	EXPECT_EQ(num_ro_pages_in_data, 1);

	num_pages = align_up((image_end - data_end), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(data_end, PAGE_SIZE);

	while (num_pages) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	/* Check that permissions on an invalid address returns error */
	struct ffa_value res = ffa_mem_perm_get(0xDEADBEEF);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	res = ffa_mem_perm_get(0x0);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp(ffa_receiver(ret), ffa_sender(ret), 0, 0, 0, 0,
				 0);
}

TEST_SERVICE(ffa_mem_perm_set)
{
	struct ffa_value ret = ffa_msg_wait();

	uint64_t num_pages = 0;
	uint64_t base_va = 0;

	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);

	num_pages = 1;
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	struct ffa_value res = ffa_mem_perm_get(base_va);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
	EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);

	res = ffa_mem_perm_set(base_va, num_pages, FFA_MEM_PERM_RO);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_mem_perm_get(base_va);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
	EXPECT_EQ(res.arg2, FFA_MEM_PERM_RO);

	res = ffa_mem_perm_set(base_va, num_pages, FFA_MEM_PERM_RW);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_mem_perm_get(base_va);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
	EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);

	/* ensure permission for invalid pages cannot be changed */
	res = ffa_mem_perm_set(0xDEADBEEF, 0x1000, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	res = ffa_mem_perm_set(0x0, 0x1000, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	/* Ensure permissions cannot be changed for an unaligned, but valid
	 * address */
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	res = ffa_mem_perm_set((base_va + 1), 1, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	/*
	 * Ensure permissions cannot be changed for valid address that crosses
	 * boundary into invalid address */
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	res = ffa_mem_perm_set(base_va, 256, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	/* Esnure permissions cannot be changed using invalid attributes */
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	res = ffa_mem_perm_set(base_va, 1, 0x1);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	ffa_msg_send_direct_resp(ffa_receiver(ret), ffa_sender(ret), 0, 0, 0, 0,
				 0);
}
