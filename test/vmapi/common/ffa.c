/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "hf/mm.h"
#include "hf/static_assert.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

static alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
static alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];
static_assert(sizeof(send_page) == PAGE_SIZE, "Send page is not a page.");
static_assert(sizeof(recv_page) == PAGE_SIZE, "Recv page is not a page.");

static hf_ipaddr_t send_page_addr = (hf_ipaddr_t)send_page;
static hf_ipaddr_t recv_page_addr = (hf_ipaddr_t)recv_page;

struct mailbox_buffers set_up_mailbox(void)
{
	ASSERT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	return (struct mailbox_buffers){
		.send = send_page,
		.recv = recv_page,
	};
}

/*
 * Helper function to send memory to a VM then send a message with the retrieve
 * request it needs to retrieve it.
 */
ffa_memory_handle_t send_memory_and_retrieve_request(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	ffa_vm_id_t recipient,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access)
{
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t msg_size;
	struct ffa_value ret;
	const ffa_memory_handle_t INVALID_FRAGMENT_HANDLE = 0xffffffffffffffff;
	ffa_memory_handle_t fragment_handle = INVALID_FRAGMENT_HANDLE;
	ffa_memory_handle_t handle;
	uint32_t remaining_constituent_count;
	uint32_t sent_length;

	/* Send the first fragment of the memory. */
	remaining_constituent_count = ffa_memory_region_init(
		tx_buffer, HF_MAILBOX_SIZE, sender, recipient, constituents,
		constituent_count, 0, flags, send_data_access,
		send_instruction_access, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_OUTER_SHAREABLE,
		&total_length, &fragment_length);
	if (remaining_constituent_count == 0) {
		EXPECT_EQ(total_length, fragment_length);
	}
	switch (share_func) {
	case FFA_MEM_DONATE_32:
		ret = ffa_mem_donate(total_length, fragment_length);
		break;
	case FFA_MEM_LEND_32:
		ret = ffa_mem_lend(total_length, fragment_length);
		break;
	case FFA_MEM_SHARE_32:
		ret = ffa_mem_share(total_length, fragment_length);
		break;
	default:
		FAIL("Invalid share_func %#x.\n", share_func);
		/* Never reached, but needed to keep clang-analyser happy. */
		return 0;
	}
	sent_length = fragment_length;

	/* Send the remaining fragments. */
	while (remaining_constituent_count != 0) {
		dlog_verbose("%d constituents left to send.\n",
			     remaining_constituent_count);
		EXPECT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
		if (fragment_handle == INVALID_FRAGMENT_HANDLE) {
			fragment_handle = ffa_frag_handle(ret);
		} else {
			EXPECT_EQ(ffa_frag_handle(ret), fragment_handle);
		}
		EXPECT_EQ(ret.arg3, sent_length);
		/* Sender MBZ at virtual instance. */
		EXPECT_EQ(ffa_frag_sender(ret), 0);

		remaining_constituent_count = ffa_memory_fragment_init(
			tx_buffer, HF_MAILBOX_SIZE,
			constituents + constituent_count -
				remaining_constituent_count,
			remaining_constituent_count, &fragment_length);

		ret = ffa_mem_frag_tx(fragment_handle, fragment_length);
		sent_length += fragment_length;
	}

	EXPECT_EQ(sent_length, total_length);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	handle = ffa_mem_success_handle(ret);
	EXPECT_EQ(handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK,
		  FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR);
	if (fragment_handle != INVALID_FRAGMENT_HANDLE) {
		EXPECT_EQ(handle, fragment_handle);
	}

	/*
	 * Send the appropriate retrieve request to the VM so that it can use it
	 * to retrieve the memory.
	 */
	msg_size = ffa_memory_retrieve_request_init(
		tx_buffer, handle, sender, recipient, 0, 0,
		retrieve_data_access, retrieve_instruction_access,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_OUTER_SHAREABLE);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	EXPECT_EQ(ffa_msg_send(sender, recipient, msg_size, 0).func,
		  FFA_SUCCESS_32);

	return handle;
}

/*
 * Helper function to send memory to a VM then send a message with the retrieve
 * request it needs to retrieve it, forcing the request to be made in at least
 * two fragments even if it could fit in one.
 */
ffa_memory_handle_t send_memory_and_retrieve_request_force_fragmented(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	ffa_vm_id_t recipient,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access)
{
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t msg_size;
	uint32_t remaining_constituent_count;
	struct ffa_value ret;
	ffa_memory_handle_t handle;

	/* Send everything except the last constituent in the first fragment. */
	remaining_constituent_count = ffa_memory_region_init(
		tx_buffer, HF_MAILBOX_SIZE, sender, recipient, constituents,
		constituent_count, 0, flags, send_data_access,
		send_instruction_access, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_OUTER_SHAREABLE,
		&total_length, &fragment_length);
	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(total_length, fragment_length);
	/* Don't include the last constituent in the first fragment. */
	fragment_length -= sizeof(struct ffa_memory_region_constituent);
	switch (share_func) {
	case FFA_MEM_DONATE_32:
		ret = ffa_mem_donate(total_length, fragment_length);
		break;
	case FFA_MEM_LEND_32:
		ret = ffa_mem_lend(total_length, fragment_length);
		break;
	case FFA_MEM_SHARE_32:
		ret = ffa_mem_share(total_length, fragment_length);
		break;
	default:
		FAIL("Invalid share_func %#x.\n", share_func);
		/* Never reached, but needed to keep clang-analyser happy. */
		return 0;
	}
	EXPECT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	EXPECT_EQ(ret.arg3, fragment_length);
	/* Sender MBZ at virtual instance. */
	EXPECT_EQ(ffa_frag_sender(ret), 0);

	handle = ffa_frag_handle(ret);

	/* Send the last constituent in a separate fragment. */
	remaining_constituent_count = ffa_memory_fragment_init(
		tx_buffer, HF_MAILBOX_SIZE,
		&constituents[constituent_count - 1], 1, &fragment_length);
	EXPECT_EQ(remaining_constituent_count, 0);
	ret = ffa_mem_frag_tx(handle, fragment_length);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_success_handle(ret), handle);

	/*
	 * Send the appropriate retrieve request to the VM so that it can use it
	 * to retrieve the memory.
	 */
	msg_size = ffa_memory_retrieve_request_init(
		tx_buffer, handle, sender, recipient, 0, 0,
		retrieve_data_access, retrieve_instruction_access,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_OUTER_SHAREABLE);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	EXPECT_EQ(ffa_msg_send(sender, recipient, msg_size, 0).func,
		  FFA_SUCCESS_32);

	return handle;
}

/*
 * Use the retrieve request from the receive buffer to retrieve a memory region
 * which has been sent to us. Copies all the fragments into the provided buffer
 * if any, and checks that the total length of all fragments is no more than
 * `memory_region_max_size`. Returns the sender, and the handle via a return
 * parameter.
 */
ffa_vm_id_t retrieve_memory_from_message(
	void *recv_buf, void *send_buf, struct ffa_value msg_ret,
	ffa_memory_handle_t *handle,
	struct ffa_memory_region *memory_region_ret,
	size_t memory_region_max_size)
{
	uint32_t msg_size;
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;
	ffa_vm_id_t sender;
	struct ffa_memory_region *retrieve_request;
	ffa_memory_handle_t handle_;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t fragment_offset;

	EXPECT_EQ(msg_ret.func, FFA_MSG_SEND_32);
	msg_size = ffa_msg_send_size(msg_ret);
	sender = ffa_msg_send_sender(msg_ret);

	retrieve_request = (struct ffa_memory_region *)recv_buf;
	handle_ = retrieve_request->handle;
	if (handle != NULL) {
		*handle = handle_;
	}
	memcpy_s(send_buf, HF_MAILBOX_SIZE, recv_buf, msg_size);
	ffa_rx_release();
	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_MEM_RETRIEVE_RESP_32);
	total_length = ret.arg1;
	fragment_length = ret.arg2;
	EXPECT_GE(fragment_length,
		  sizeof(struct ffa_memory_region) +
			  sizeof(struct ffa_memory_access) +
			  sizeof(struct ffa_composite_memory_region));
	EXPECT_LE(fragment_length, HF_MAILBOX_SIZE);
	EXPECT_LE(fragment_length, total_length);
	memory_region = (struct ffa_memory_region *)recv_buf;
	EXPECT_EQ(memory_region->receiver_count, 1);
	EXPECT_EQ(memory_region->receivers[0].receiver_permissions.receiver,
		  hf_vm_get_id());

	/* Copy into the return buffer. */
	if (memory_region_ret != NULL) {
		memcpy_s(memory_region_ret, memory_region_max_size,
			 memory_region, fragment_length);
	}

	/*
	 * Release the RX buffer now that we have read everything we need from
	 * it.
	 */
	memory_region = NULL;
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Retrieve the remaining fragments. */
	fragment_offset = fragment_length;
	while (fragment_offset < total_length) {
		ret = ffa_mem_frag_rx(handle_, fragment_offset);
		EXPECT_EQ(ret.func, FFA_MEM_FRAG_TX_32);
		EXPECT_EQ(ffa_frag_handle(ret), handle_);
		/* Sender MBZ at virtual instance. */
		EXPECT_EQ(ffa_frag_sender(ret), 0);
		fragment_length = ret.arg3;
		EXPECT_GT(fragment_length, 0);
		ASSERT_LE(fragment_offset + fragment_length,
			  memory_region_max_size);
		if (memory_region_ret != NULL) {
			memcpy_s((uint8_t *)memory_region_ret + fragment_offset,
				 memory_region_max_size - fragment_offset,
				 recv_buf, fragment_length);
		}
		fragment_offset += fragment_length;
		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	}
	EXPECT_EQ(fragment_offset, total_length);

	return sender;
}

/*
 * Use the retrieve request from the receive buffer to retrieve a memory region
 * which has been sent to us, expecting it to fail with the given error code.
 * Returns the sender.
 */
ffa_vm_id_t retrieve_memory_from_message_expect_fail(void *recv_buf,
						     void *send_buf,
						     struct ffa_value msg_ret,
						     int32_t expected_error)
{
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_vm_id_t sender;

	EXPECT_EQ(msg_ret.func, FFA_MSG_SEND_32);
	msg_size = ffa_msg_send_size(msg_ret);
	sender = ffa_msg_send_sender(msg_ret);

	memcpy_s(send_buf, HF_MAILBOX_SIZE, recv_buf, msg_size);
	ffa_rx_release();
	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	EXPECT_FFA_ERROR(ret, expected_error);

	return sender;
}
