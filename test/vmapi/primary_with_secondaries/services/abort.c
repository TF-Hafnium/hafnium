/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

alignas(PAGE_SIZE) static uint8_t pages[2 * PAGE_SIZE];

TEST_SERVICE(data_abort)
{
	/* Not using NULL so static analysis doesn't complain. */
	int *p = (int *)1;
	*p = 12;
}

TEST_SERVICE(straddling_data_abort)
{
	void *send_buf = SERVICE_SEND_BUFFER();
	/* Give some memory to the primary VM so that it's unmapped. */
	struct spci_memory_region_constituent constituents[] = {
		{.address = (uint64_t)(&pages[PAGE_SIZE]), .page_count = 1},
	};
	uint32_t msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		ARRAY_SIZE(constituents), 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, msg_size,
				SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
			  .func,
		  SPCI_SUCCESS_32);

	*(volatile uint64_t *)(&pages[PAGE_SIZE - 6]);
}

TEST_SERVICE(instruction_abort)
{
	/* Not using NULL so static analysis doesn't complain. */
	int (*f)(void) = (int (*)(void))4;
	f();
}

TEST_SERVICE(straddling_instruction_abort)
{
	void *send_buf = SERVICE_SEND_BUFFER();

	/*
	 * Get a function pointer which, when branched to, will attempt to
	 * execute a 4-byte instruction straddling two pages.
	 */
	int (*f)(void) = (int (*)(void))(&pages[PAGE_SIZE - 2]);

	/* Give second page to the primary VM so that it's unmapped. */
	struct spci_memory_region_constituent constituents[] = {
		{.address = (uint64_t)(&pages[PAGE_SIZE]), .page_count = 1},
	};
	uint32_t msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		ARRAY_SIZE(constituents), 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, msg_size,
				SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
			  .func,
		  SPCI_SUCCESS_32);

	/* Branch to instruction whose 2 bytes are now in an unmapped page. */
	f();
}
