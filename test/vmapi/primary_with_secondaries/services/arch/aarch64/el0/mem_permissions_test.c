/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/**
 * This must match the size specified for services1.
 */
extern uint8_t volatile text_begin[];
extern uint8_t volatile text_end[];
extern uint8_t volatile rodata_begin[];
extern uint8_t volatile rodata_end[];
extern uint8_t volatile data_begin[];
extern uint8_t volatile data_end[];
extern uint8_t volatile stacks_begin[];
extern uint8_t volatile stacks_end[];
extern uint8_t volatile image_end[];

/**
 * ffa_mem_perm_set_ro must be run separately from ffa_mem_perm_get and
 * ffa_mem_perm_set as ffa_mem_perm_set_ro changes the memory permissions
 * of the data section which causes the tests to fail.
 */
/**
 * ffa_mem_perm_get tests the FFA_MEM_PERM_GET interface by getting the memory
 * permissions for the various memory sections and checking they match the
 * exepected default.
 */
SERVICE_SET_UP(ffa_mem_perm_get)
{
	uint64_t num_pages = 0;
	uint64_t base_va = 0;
	/* Hafnium may use rx/tx buffers so one page may be marked as RO. */
	uint32_t num_ro_pages_in_data = 0;

	num_pages = align_up((text_end - text_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(text_begin, PAGE_SIZE);

	while (num_pages != 0U) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RX);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	num_pages =
		align_up((rodata_end - rodata_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(rodata_begin, PAGE_SIZE);

	while (num_pages != 0) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RO);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	num_pages = align_up((data_end - data_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);

	while (num_pages != 0) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		if (res.arg2 == FFA_MEM_PERM_RO) {
			/**
			 * Hafnium may use rx/tx buffers so one page may be
			 * marked as RO.
			 */
			num_ro_pages_in_data++;
		} else {
			EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);
		}
		base_va += PAGE_SIZE;
		num_pages--;
	}
	EXPECT_EQ(num_ro_pages_in_data, 1);

	num_pages =
		align_up((stacks_end - stacks_begin), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(stacks_begin, PAGE_SIZE);

	while (num_pages != 0) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	num_pages = align_up((image_end - data_end), PAGE_SIZE) / PAGE_SIZE;
	base_va = (uint64_t)align_down(data_end, PAGE_SIZE);

	while (num_pages != 0) {
		struct ffa_value res = ffa_mem_perm_get(base_va);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);
		base_va += PAGE_SIZE;
		num_pages--;
	}

	/* Check that permissions on an invalid address returns error. */
	struct ffa_value res = ffa_mem_perm_get(0xDEADBEEF);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	res = ffa_mem_perm_get(0x0);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);
}

/**
 * ffa_mem_perm_set tests the FFA_MEM_PERM_SET interface by setting the
 * permissions of various memory sections and checking the permissions are
 * changed using FFA_MEM_PERM_GET. It also checks invalid pages cannot be
 * changed. Note this test changes the permission of the memory section back to
 * their original so as not to change the testing environment for runtime tests.
 */
SERVICE_SET_UP(ffa_mem_perm_set)
{
	uint64_t num_pages = 0;
	uint64_t base_va = 0;

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

	/* Ensure permission for invalid pages cannot be changed. */
	res = ffa_mem_perm_set(0xDEADBEEF, 0x1000, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	res = ffa_mem_perm_set(0x0, 0x1000, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	/**
	 * Ensure permissions cannot be changed for an unaligned, but valid
	 * address.
	 */
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	res = ffa_mem_perm_set((base_va + 1), 1, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	/**
	 * Ensure permissions cannot be changed for valid address that crosses
	 * boundary into invalid address.
	 */
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	res = ffa_mem_perm_set(base_va, 256, FFA_MEM_PERM_RX);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);

	/* Ensure permissions cannot be changed using invalid attributes. */
	base_va = (uint64_t)align_down(data_begin, PAGE_SIZE);
	res = ffa_mem_perm_set(base_va, 1, 0x1);
	EXPECT_EQ(res.func, FFA_ERROR_32);
	EXPECT_EQ(ffa_error_code(res), FFA_INVALID_PARAMETERS);
}

/**
 * This setup function is to be used along side the
 * ffa_mem_perm_set_ro_fails_write TEST and ffa_mem_perm_set_ro_fails_write
 * TEST_SERVICE. It sets the memory permission of the data section to RO for
 * the SP and ffa_mem_perm_set_ro_fails_write then checks that writing to
 * this section throws an exception.
 */
SERVICE_SET_UP(ffa_mem_perm_set_ro)
{
	uint64_t num_pages = 0;
	uint64_t base_va = 0;

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
}

/**
 * To be executed along side the ffa_mem_perm_set_ro SERVICE_SET_UP function.
 */
TEST_SERVICE(ffa_mem_perm_set_ro_fails_write)
{
	*data_begin = 0xFF;
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
}
