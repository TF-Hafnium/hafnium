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

/*
 * This must match the size specified for services1 in
 * //test/vmapi/el0_partitions/manifest.dts.
 */
#define SECONDARY_MEMORY_SIZE 1048576

extern uint8_t volatile text_begin[];

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
