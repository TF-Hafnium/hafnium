/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mm.h"

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

static void expect_get_valid(uintvaddr_t base_va, uint64_t perm)
{
	struct ffa_value res = ffa_mem_perm_get(base_va);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
	EXPECT_EQ(res.arg2, perm);
}

static void expect_get_invalid(uintvaddr_t base_va)
{
	struct ffa_value res = ffa_mem_perm_get(base_va);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

static void expect_set_valid(uintvaddr_t base_va, uint32_t page_count,
			     uint64_t perm)
{
	struct ffa_value res = ffa_mem_perm_set(base_va, page_count, perm);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
}

static void expect_set_invalid(uintvaddr_t base_va, uint32_t page_count,
			       uint64_t perm)
{
	struct ffa_value res = ffa_mem_perm_set(base_va, page_count, perm);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Assert that every page in the range `start` to `end` has the expected
 * permissions.
 */
static void test_perm_get_range(volatile uint8_t* start, volatile uint8_t* end,
				uint32_t perm)
{
	const uint32_t num_pages = align_up(end - start, PAGE_SIZE) / PAGE_SIZE;
	uintvaddr_t base_va = (uintvaddr_t)align_down(start, PAGE_SIZE);

	for (size_t i = 0; i < num_pages; i++) {
		expect_get_valid(base_va, perm);
		base_va += PAGE_SIZE;
	}
}

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
	/* Hafnium may use rx/tx buffers so one page may be marked as RO. */
	uint32_t num_ro_pages_in_data = 0;

	const uint32_t num_pages =
		align_up(data_end - data_begin, PAGE_SIZE) / PAGE_SIZE;
	uintvaddr_t base_va = (uintvaddr_t)align_down(data_begin, PAGE_SIZE);

	for (size_t i = 0; i < num_pages; i++) {
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
	}
	EXPECT_EQ(num_ro_pages_in_data, 1);

	test_perm_get_range(text_begin, text_end, FFA_MEM_PERM_RX);
	test_perm_get_range(rodata_begin, rodata_end, FFA_MEM_PERM_RO);
	test_perm_get_range(stacks_begin, stacks_end, FFA_MEM_PERM_RW);
	test_perm_get_range(data_end, image_end, FFA_MEM_PERM_RW);

	/* Check that permissions on an invalid address returns error. */
	expect_get_invalid(0xDEADBEEF);
	expect_get_invalid(0x0);
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
	uintvaddr_t base_va = (uintvaddr_t)align_down(data_begin, PAGE_SIZE);
	expect_get_valid(base_va, FFA_MEM_PERM_RW);

	expect_set_valid(base_va, 1, FFA_MEM_PERM_RO);
	expect_get_valid(base_va, FFA_MEM_PERM_RO);

	expect_set_valid(base_va, 1, FFA_MEM_PERM_RW);
	expect_get_valid(base_va, FFA_MEM_PERM_RW);

	/* Ensure permission for invalid pages cannot be changed. */
	expect_set_invalid(0xDEADBEEF, 0x1000, FFA_MEM_PERM_RX);
	expect_set_invalid(0x0, 0x1000, FFA_MEM_PERM_RX);

	/**
	 * Ensure permissions cannot be changed for an unaligned, but valid
	 * address.
	 */
	expect_set_invalid(base_va + 1, 1, FFA_MEM_PERM_RX);

	/**
	 * Ensure permissions cannot be changed for valid address that crosses
	 * boundary into invalid address.
	 */
	expect_set_invalid(base_va, 256, FFA_MEM_PERM_RX);

	/* Ensure permissions cannot be changed using invalid attributes. */
	expect_set_invalid(base_va, 1, 0x1);
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
	uintvaddr_t base_va = (uintvaddr_t)align_down(data_begin, PAGE_SIZE);
	expect_get_valid(base_va, FFA_MEM_PERM_RW);

	expect_set_valid(base_va, 1, FFA_MEM_PERM_RO);
	expect_get_valid(base_va, FFA_MEM_PERM_RO);
}

/**
 * To be executed along side the ffa_mem_perm_set_ro SERVICE_SET_UP function.
 */
TEST_SERVICE(ffa_mem_perm_set_ro_fails_write)
{
	*data_begin = 0xFF;
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
}
