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

static void expect_get_valid(uintvaddr_t base_va, uint32_t page_count,
			     uint32_t expected_page_count,
			     enum ffa_mem_perm expected_perm)
{
	struct ffa_value res = ffa_mem_perm_get(base_va, page_count);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
	EXPECT_EQ(res.arg2, expected_perm);
	EXPECT_EQ(res.arg3, expected_page_count - 1);
}

static void expect_get_full_valid(uintvaddr_t base_va, uint32_t page_count,
				  enum ffa_mem_perm expected_perm)
{
	expect_get_valid(base_va, page_count, page_count, expected_perm);
}

static void expect_get_invalid(uintvaddr_t base_va, uint32_t page_count)
{
	struct ffa_value res = ffa_mem_perm_get(base_va, page_count);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

static void expect_set_valid(uintvaddr_t base_va, uint32_t page_count,
			     enum ffa_mem_perm perm)
{
	struct ffa_value res = ffa_mem_perm_set(base_va, page_count, perm);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);
}

static void expect_set_invalid(uintvaddr_t base_va, uint32_t page_count,
			       enum ffa_mem_perm perm)
{
	struct ffa_value res = ffa_mem_perm_set(base_va, page_count, perm);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

static uint32_t range_page_count(volatile uint8_t *start, volatile uint8_t *end)
{
	return align_up(end - start, PAGE_SIZE) / PAGE_SIZE;
}

/**
 * Assert that every page in the range `start` to `expected_end` has the
 * expected permissions.
 */
static void test_perm_get_range(volatile uint8_t *start, volatile uint8_t *end,
				volatile uint8_t *expected_end,
				enum ffa_mem_perm perm)
{
	assert(start <= end);

	const uint32_t num_pages = range_page_count(start, end);
	const uint32_t expected_num_pages =
		range_page_count(start, expected_end);
	uintvaddr_t base_va = (uintvaddr_t)align_down(start, PAGE_SIZE);

	if (num_pages > 0) {
		expect_get_valid(base_va, num_pages, expected_num_pages, perm);
	}

	for (size_t i = 0; i < expected_num_pages; i++) {
		expect_get_full_valid(base_va, 1, perm);
		base_va += PAGE_SIZE;
	}
}

/**
 * Assert that every page in the range `start` to `end` has the expected
 * permissions.
 */
static void test_perm_get_range_full(volatile uint8_t *start,
				     volatile uint8_t *end,
				     enum ffa_mem_perm perm)
{
	test_perm_get_range(start, end, end, perm);
}

static void print_range(const char *name, volatile uint8_t *start,
			volatile uint8_t *end)
{
	dlog_verbose("%s: %p - %p (%u pages)\n", name, (void *)start,
		     (void *)end, range_page_count(start, end));
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

	const uint32_t num_pages = range_page_count(data_begin, data_end);
	uintvaddr_t base_va = (uintvaddr_t)align_down(data_begin, PAGE_SIZE);
	volatile uint8_t *rx_start = NULL;
	volatile uint8_t *tx_start = NULL;
	volatile uint8_t *rx_end = NULL;

	print_range("text", text_begin, text_end);
	print_range("rodata", rodata_begin, rodata_end);
	print_range("data", data_begin, data_end);
	print_range("stacks", stacks_begin, stacks_end);

	for (size_t i = 0; i < num_pages; i++) {
		struct ffa_value res = ffa_mem_perm_get(base_va, 1);
		EXPECT_EQ(res.func, FFA_SUCCESS_32);
		if (res.arg2 == FFA_MEM_PERM_RO) {
			/**
			 * Hafnium may use rx/tx buffers so one page may be
			 * marked as RO.
			 */
			num_ro_pages_in_data++;

			/* NOLINTNEXTLINE(performance-no-int-to-ptr)*/
			rx_start = (volatile uint8_t *)base_va;
			rx_end = rx_start + PAGE_SIZE;
			tx_start = rx_start - PAGE_SIZE;
		} else {
			EXPECT_EQ(res.arg2, FFA_MEM_PERM_RW);
		}
		base_va += PAGE_SIZE;
	}
	EXPECT_EQ(num_ro_pages_in_data, 1);

	test_perm_get_range_full(text_begin, text_end, FFA_MEM_PERM_RX);
	test_perm_get_range_full(rodata_begin, rodata_end, FFA_MEM_PERM_RO);
	test_perm_get_range_full(stacks_begin, stacks_end, FFA_MEM_PERM_RW);
	test_perm_get_range_full(data_end, image_end, FFA_MEM_PERM_RW);

	test_perm_get_range(text_begin, image_end, text_end, FFA_MEM_PERM_RX);
	test_perm_get_range(rodata_begin, image_end, rodata_end,
			    FFA_MEM_PERM_RO);

	test_perm_get_range(data_begin, image_end, tx_start, FFA_MEM_PERM_RW);
	/*
	 * The TX page has the same permissions as the rest of data, but
	 * different mode, so `mm_get_mode_partial` will treat them as
	 * different.
	 */
	test_perm_get_range(tx_start, image_end, rx_start, FFA_MEM_PERM_RW);
	test_perm_get_range(rx_start, image_end, rx_end, FFA_MEM_PERM_RO);
	test_perm_get_range(rx_end, image_end, data_end, FFA_MEM_PERM_RW);

	test_perm_get_range(stacks_begin, image_end, stacks_end,
			    FFA_MEM_PERM_RW);
	test_perm_get_range(data_end, image_end, image_end, FFA_MEM_PERM_RW);

	expect_get_valid((uintvaddr_t)text_end - PAGE_SIZE, 2, 1,
			 FFA_MEM_PERM_RX);

	/* Failure: unmapped base address */
	expect_get_invalid(0x0, 1);
	expect_get_invalid(0xDEADBEEF, 1);

	/* Failure: unaligned base address */
	expect_get_invalid((uintvaddr_t)text_begin + 1, 1);

	/* Failure: empty range */
	expect_get_invalid((uintvaddr_t)text_begin, 0);

	/* Failure: overflow */
	expect_get_invalid(UINT64_MAX, 1);
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
	expect_get_full_valid(base_va, 1, FFA_MEM_PERM_RW);

	expect_set_valid(base_va, 1, FFA_MEM_PERM_RO);
	expect_get_full_valid(base_va, 1, FFA_MEM_PERM_RO);

	expect_set_valid(base_va, 1, FFA_MEM_PERM_RW);
	expect_get_full_valid(base_va, 1, FFA_MEM_PERM_RW);

	/* Failure: unmapped base address */
	expect_set_invalid(0x0, 1, FFA_MEM_PERM_RX);
	expect_set_invalid(0xDEADBEEF, 1, FFA_MEM_PERM_RX);

	/* Failure: unaligned base address */
	expect_set_invalid(base_va + 1, 1, FFA_MEM_PERM_RX);

	/* Failure: base address is valid, but end address is invalid */
	expect_set_invalid(base_va, 256, FFA_MEM_PERM_RX);

	/* Failure: empty range */
	expect_set_invalid((uintvaddr_t)text_begin, 0, FFA_MEM_PERM_RX);

	/* Failure: overflow */
	expect_set_invalid(UINT64_MAX, 1, FFA_MEM_PERM_RX);

	/* Failure: invalid attributes */
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
	expect_get_full_valid(base_va, 1, FFA_MEM_PERM_RW);

	expect_set_valid(base_va, 1, FFA_MEM_PERM_RO);
	expect_get_full_valid(base_va, 1, FFA_MEM_PERM_RO);
}

/**
 * To be executed along side the ffa_mem_perm_set_ro SERVICE_SET_UP function.
 */
TEST_SERVICE(ffa_mem_perm_set_ro_fails_write)
{
	*data_begin = 0xFF;
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
}
