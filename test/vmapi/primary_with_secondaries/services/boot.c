/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stddef.h>
#include <stdint.h>

#include "hf/arch/mmu.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/ffa_partition_manifest.h"
#include "hf/mm.h"
#include "hf/panic.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/hftest_impl.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

/*
 * This must match the size specified for services1 in
 * //test/vmapi/primary_with_secondaries:primary_with_secondaries_test.
 */
#define SECONDARY_MEMORY_SIZE 1048576

extern uint8_t volatile text_begin[];

/*
 * SVMs are not yet receiving their manifest.
 * SPs do not have text_begin set to load_address.
 * TODO: use address as set in the manifest for both VMs and SPs.
 */
static uintptr_t get_load_address(struct hftest_context* ctx)
{
	if (ctx->is_ffa_manifest_parsed) {
		return ctx->partition_manifest.load_addr;
	}

	return (uintptr_t)&text_begin[0];
}

static void update_region_security_state(struct memory_region* mem_region)
{
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	void* address = (void*)mem_region->base_address;
	size_t page_count = mem_region->page_count;
	uint32_t attributes = mem_region->attributes;

	uint32_t mode = 0;
	uint32_t extra_attributes =
		(attributes & MANIFEST_REGION_ATTR_SECURITY) != 0 ? MM_MODE_NS
								  : 0U;

	if (!hftest_mm_get_mode(address, FFA_PAGE_SIZE * page_count, &mode)) {
		FAIL("Memory range has different modes.\n");
	}

	hftest_mm_identity_map(address, FFA_PAGE_SIZE * page_count,
			       mode | extra_attributes);
}

TEST_SERVICE(boot_memory)
{
	struct hftest_context* ctx = hftest_get_context();
	uint8_t checksum = 0;
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	uint8_t* mem_ptr = (uint8_t*)get_load_address(ctx);

	/* Check that the size passed in by Hafnium is what is expected. */
	ASSERT_EQ(SERVICE_MEMORY_SIZE(), SECONDARY_MEMORY_SIZE);

	/*
	 * Check that we can read all memory up to the given size. Calculate a
	 * basic checksum and check that it is non-zero, as a double-check that
	 * we are actually reading something.
	 */
	for (size_t i = 0; i < SERVICE_MEMORY_SIZE(); ++i) {
		checksum += mem_ptr[i];
	}
	ASSERT_NE(checksum, 0);

	ffa_yield();
}

TEST_SERVICE(boot_memory_underrun)
{
	struct hftest_context* ctx = hftest_get_context();
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	uint8_t* mem_ptr = (uint8_t*)get_load_address(ctx);
	exception_setup(NULL, exception_handler_yield_data_abort);
	/*
	 * Try to read memory below the start of the image. This should result
	 * in the VM trapping and yielding.
	 */
	dlog("Read memory below limit: %d\n", mem_ptr[-1]);
	FAIL("Managed to read memory below limit");
}

TEST_SERVICE(boot_memory_overrun)
{
	struct hftest_context* ctx = hftest_get_context();
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	uint8_t* mem_ptr = (uint8_t*)get_load_address(ctx);
	exception_setup(NULL, exception_handler_yield_data_abort);
	/*
	 * Try to read memory above the limit defined by memory_size. This
	 * should result in the VM trapping and yielding.
	 */
	dlog("Read memory above limit: %d\n", mem_ptr[SERVICE_MEMORY_SIZE()]);
	FAIL("Managed to read memory above limit");
}

/*
 * Access all memory regions provided to the SP.
 */
TEST_SERVICE(boot_memory_manifest)
{
	uint8_t* mem_ptr;
	struct hftest_context* ctx = hftest_get_context();
	struct memory_region* mem_region;
	uint32_t regions_count;

	if (!ctx->is_ffa_manifest_parsed) {
		panic("This test requires the running partition to have "
		      "received and parsed its own FF-A manifest.\n");
	}

	regions_count = ctx->partition_manifest.mem_region_count;

	ASSERT_TRUE(regions_count != 0U);

	/* Try to access all regions defined. */
	for (uint32_t i = 0; i < regions_count; i++) {
		uint64_t checksum = 0;
		mem_region = &ctx->partition_manifest.mem_regions[i];

		HFTEST_LOG("Accessing memory: %#lx - %u pages - %#x attributes",
			   mem_region->base_address, mem_region->page_count,
			   mem_region->attributes);

		ASSERT_NE(mem_region->attributes & MM_MODE_R, 0);

		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		mem_ptr = (uint8_t*)mem_region->base_address;

		update_region_security_state(mem_region);

		if ((mem_region->attributes & MM_MODE_W) != 0) {
			for (size_t i = 0;
			     i < mem_region->page_count * PAGE_SIZE; ++i) {
				mem_ptr[i] = (uint8_t)i / 2;
				checksum += (uint64_t)mem_ptr[i];
			}

			ASSERT_NE(checksum, 0);
		} else {
			for (size_t i = 0;
			     i < mem_region->page_count * PAGE_SIZE; ++i) {
				ASSERT_NE(mem_ptr[i], 0);
			}
		}
	}
	ffa_yield();
}
