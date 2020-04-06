/*
 * Copyright 2018 The Hafnium Authors.
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

#include "hf/spci.h"

#include "hf/mm.h"
#include "hf/static_assert.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/spci.h"

static alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
static alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];
static_assert(sizeof(send_page) == PAGE_SIZE, "Send page is not a page.");
static_assert(sizeof(recv_page) == PAGE_SIZE, "Recv page is not a page.");

static hf_ipaddr_t send_page_addr = (hf_ipaddr_t)send_page;
static hf_ipaddr_t recv_page_addr = (hf_ipaddr_t)recv_page;

struct mailbox_buffers set_up_mailbox(void)
{
	ASSERT_EQ(spci_rxtx_map(send_page_addr, recv_page_addr).func,
		  SPCI_SUCCESS_32);
	return (struct mailbox_buffers){
		.send = send_page,
		.recv = recv_page,
	};
}

/*
 * Helper function to send memory to a VM then send a message with the retrieve
 * request it needs to retrieve it.
 */
spci_memory_handle_t send_memory_and_retrieve_request(
	uint32_t share_func, void *tx_buffer, spci_vm_id_t sender,
	spci_vm_id_t recipient,
	struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count, spci_memory_region_flags_t flags,
	enum spci_data_access send_data_access,
	enum spci_data_access retrieve_data_access,
	enum spci_instruction_access send_instruction_access,
	enum spci_instruction_access retrieve_instruction_access)
{
	uint32_t msg_size;
	struct spci_value ret;
	spci_memory_handle_t handle;

	/* Send the memory. */
	msg_size = spci_memory_region_init(
		tx_buffer, sender, recipient, constituents, constituent_count,
		0, flags, send_data_access, send_instruction_access,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	switch (share_func) {
	case SPCI_MEM_DONATE_32:
		ret = spci_mem_donate(msg_size, msg_size);
		break;
	case SPCI_MEM_LEND_32:
		ret = spci_mem_lend(msg_size, msg_size);
		break;
	case SPCI_MEM_SHARE_32:
		ret = spci_mem_share(msg_size, msg_size);
		break;
	default:
		FAIL("Invalid share_func %#x.\n", share_func);
		/* Never reached, but needed to keep clang-analyser happy. */
		return 0;
	}
	EXPECT_EQ(ret.func, SPCI_SUCCESS_32);
	handle = spci_mem_success_handle(ret);

	/*
	 * Send the appropriate retrieve request to the VM so that it can use it
	 * to retrieve the memory.
	 */
	msg_size = spci_memory_retrieve_request_init(
		tx_buffer, handle, sender, recipient, 0, 0,
		retrieve_data_access, retrieve_instruction_access,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(sender, recipient, msg_size, 0).func,
		  SPCI_SUCCESS_32);

	return handle;
}

/*
 * Use the retrieve request from the receive buffer to retrieve a memory region
 * which has been sent to us. Returns the sender, and the handle via a return
 * parameter.
 */
spci_vm_id_t retrieve_memory_from_message(void *recv_buf, void *send_buf,
					  struct spci_value msg_ret,
					  spci_memory_handle_t *handle)
{
	uint32_t msg_size;
	struct spci_value ret;
	struct spci_memory_region *memory_region;
	spci_vm_id_t sender;

	EXPECT_EQ(msg_ret.func, SPCI_MSG_SEND_32);
	msg_size = spci_msg_send_size(msg_ret);
	sender = spci_msg_send_sender(msg_ret);

	if (handle != NULL) {
		struct spci_memory_region *retrieve_request =
			(struct spci_memory_region *)recv_buf;
		*handle = retrieve_request->handle;
	}
	memcpy_s(send_buf, HF_MAILBOX_SIZE, recv_buf, msg_size);
	spci_rx_release();
	ret = spci_mem_retrieve_req(msg_size, msg_size);
	EXPECT_EQ(ret.func, SPCI_MEM_RETRIEVE_RESP_32);
	memory_region = (struct spci_memory_region *)recv_buf;
	EXPECT_EQ(memory_region->receiver_count, 1);
	EXPECT_EQ(memory_region->receivers[0].receiver_permissions.receiver,
		  hf_vm_get_id());

	return sender;
}

/*
 * Use the retrieve request from the receive buffer to retrieve a memory region
 * which has been sent to us, expecting it to fail with the given error code.
 * Returns the sender.
 */
spci_vm_id_t retrieve_memory_from_message_expect_fail(void *recv_buf,
						      void *send_buf,
						      struct spci_value msg_ret,
						      int32_t expected_error)
{
	uint32_t msg_size;
	struct spci_value ret;
	spci_vm_id_t sender;

	EXPECT_EQ(msg_ret.func, SPCI_MSG_SEND_32);
	msg_size = spci_msg_send_size(msg_ret);
	sender = spci_msg_send_sender(msg_ret);

	memcpy_s(send_buf, HF_MAILBOX_SIZE, recv_buf, msg_size);
	spci_rx_release();
	ret = spci_mem_retrieve_req(msg_size, msg_size);
	EXPECT_SPCI_ERROR(ret, expected_error);

	return sender;
}
