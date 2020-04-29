/*
 * Copyright 2020 The Hafnium Authors.
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


#include <stdint.h>

#include "hf/mm.h"
#include "hf/std.h"
#include "hf/panic.h"
#include "hf/check.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "spci_test_protocol.h"

alignas(PAGE_SIZE) static uint8_t page[PAGE_SIZE];

#define SERVICE_VM1 1

struct mailbox_buffers {
	void *send;
	void *recv;
};

static alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
static alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];
static_assert(sizeof(send_page) == PAGE_SIZE, "Send page is not a page.");
static_assert(sizeof(recv_page) == PAGE_SIZE, "Recv page is not a page.");

static hf_ipaddr_t send_page_addr = (hf_ipaddr_t)send_page;
static hf_ipaddr_t recv_page_addr = (hf_ipaddr_t)recv_page;

static struct mailbox_buffers mb;

static uint16_t sp_id;

static inline uint64_t get_constituent_addr(struct spci_memory_region_constituent *constituent)
{
	return constituent->address;
}

struct mailbox_buffers set_up_mailbox(void)
{
	ASSERT_EQ(spci_rxtx_map(send_page_addr, recv_page_addr).func,
		  SPCI_SUCCESS_32);
	return (struct mailbox_buffers){
		.send = send_page,
		.recv = recv_page,
	};
}

uint32_t get_status(struct spci_value* value)
{
	if(value->func == SPCI_ERROR_32)
	{
		return value->arg2;
	}

	return 0;
}

static alignas(PAGE_SIZE) char mem_region_buffer[4096 * 3];
#define REGION_BUF_SIZE sizeof(mem_region_buffer)

static void test_memory_share(uint32_t handle)
{
	struct spci_value spci_return;
	struct spci_retrieve_descriptor  *retrieve_desc;
	uint32_t total_length;
	uint32_t increment_length;
	uint32_t constituent_count;

	if (!mb.send)
	{
		dlog("--bare metal test VM: Tx buffer not set\n");
		return;
	}
	((struct mem_retrieve_descriptor *)mb.send)->handle = handle;

	retrieve_desc = (struct spci_retrieve_descriptor *)mem_region_buffer;

	/*address, page_count, fragment_count, length, handle*/
	spci_return = spci_mem_retrieve_req(0, 0, 0, 0, handle);

	if(spci_return.func == SPCI_ERROR_32)
	{
		dlog("--bare metal test VM: failed to retrieve mem %d\n", handle);
		return;
	}

	total_length = spci_return.arg4;
	increment_length = spci_return.arg3;

	memcpy_s(mem_region_buffer, REGION_BUF_SIZE, mb.recv, increment_length);

	while (total_length != increment_length) {
		uint32_t fragment_len;
		spci_return = spci_mem_op_resume(handle);

		if (spci_return.func == SPCI_ERROR_32)
		{
			dlog("--bare metal test VM: failed to resume mem with handle %d\n", handle);
			return;
		}
		fragment_len = spci_return.arg3;

		memcpy_s(&mem_region_buffer[increment_length], REGION_BUF_SIZE-increment_length,
			mb.recv, fragment_len);

		increment_length += fragment_len;

		CHECK(increment_length <= total_length);
		dlog("--bare metal test VM: inc_len %d, total_len %d\n", increment_length, total_length);
	}
	constituent_count = retrieve_desc->constituent_count;

	for (uint32_t index = 0; index < constituent_count; index++)
	{
		dlog("--bare metal test VM: address %#x --\n", get_constituent_addr(&retrieve_desc->constituents[index]));
		*((uint8_t *)get_constituent_addr(&retrieve_desc->constituents[index])) = 0xde;
	}

	return;
}

void noreturn kmain(const struct fdt_header *fdt)
{
	struct spci_value spci_return;
	uint32_t src_dst;

	/* set_up_mailbox calls rxtx_map. */
	mb = set_up_mailbox();
	sp_id = hf_vm_get_id();

	dlog("--bare metal test VM: start--\n");

	// TODO: enable stage-1 mappings

	/*
	 * Receive direct message.
	 *
	 * This is an impdef message where w1 states the type of request.
	 */
	// FIXME: hardcoding Secure world VM_ID as 1.
	src_dst = ((sp_id << 16) | 1);
	spci_return = spci_direct_msg_resp(src_dst, 0, 0, 0, 0, 0);

	if(get_status(&spci_return))
	{
		panic("--bare metal test VM: Error receiving message--\n");
	}

	while(1)
	{

		(void) page;

		switch (spci_return.arg3)
		{
			case FF_A_MEMORY_SHARE:
				dlog("--bare metal test VM: received a memory share request--\n");
				uint32_t handle = spci_return.arg4;

				test_memory_share(handle);

				break;

			default:
				dlog("--bare metal test VM: Unknown request ID %d--\n", spci_return.arg3);
		}
		dlog("--bare metal test VM: iteration--\n");

		/*
		 * Receive direct message.
		 *
		 * This is an impdef message where w1 states the type of request.
		 */
		src_dst = (spci_return.arg1 >> 16) |  ((spci_return.arg1 & 0xffff) << 16);
		spci_return = spci_direct_msg_resp(src_dst, 0, 0, 0, 0, 0);

		if(get_status(&spci_return))
		{
			panic("--bare metal test VM: Error receiving message--\n");
		}
	}
}
