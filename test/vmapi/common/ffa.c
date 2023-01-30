/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "hf/check.h"
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

void mailbox_unmap_buffers(struct mailbox_buffers *mb)
{
	ASSERT_EQ(ffa_rxtx_unmap().func, FFA_SUCCESS_32);
	mb->send = NULL;
	mb->recv = NULL;
}

static void send_fragmented_memory_region(
	struct ffa_value *send_ret, void *tx_buffer,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t remaining_constituent_count,
	uint32_t sent_length, uint32_t total_length,
	ffa_memory_handle_t *handle, uint64_t allocator_mask)
{
	const ffa_memory_handle_t INVALID_FRAGMENT_HANDLE = 0xffffffffffffffff;
	ffa_memory_handle_t fragment_handle = INVALID_FRAGMENT_HANDLE;
	uint32_t fragment_length;

	/* Send the remaining fragments. */
	while (remaining_constituent_count != 0) {
		dlog_verbose("%d constituents left to send.\n",
			     remaining_constituent_count);
		EXPECT_EQ(send_ret->func, FFA_MEM_FRAG_RX_32);
		if (fragment_handle == INVALID_FRAGMENT_HANDLE) {
			fragment_handle = ffa_frag_handle(*send_ret);
		} else {
			EXPECT_EQ(ffa_frag_handle(*send_ret), fragment_handle);
		}
		EXPECT_EQ(send_ret->arg3, sent_length);

		remaining_constituent_count = ffa_memory_fragment_init(
			tx_buffer, HF_MAILBOX_SIZE,
			constituents + constituent_count -
				remaining_constituent_count,
			remaining_constituent_count, &fragment_length);

		*send_ret = ffa_mem_frag_tx(fragment_handle, fragment_length);
		sent_length += fragment_length;
	}

	EXPECT_EQ(sent_length, total_length);
	EXPECT_EQ(send_ret->func, FFA_SUCCESS_32);
	*handle = ffa_mem_success_handle(*send_ret);
	EXPECT_EQ(*handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK, allocator_mask);
	if (fragment_handle != INVALID_FRAGMENT_HANDLE) {
		EXPECT_EQ(*handle, fragment_handle);
	}
}

ffa_memory_handle_t send_memory_and_retrieve_request_multi_receiver(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, struct ffa_memory_access receivers_send[],
	uint32_t receivers_send_count,
	struct ffa_memory_access receivers_retrieve[],
	uint32_t receivers_retrieve_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags)
{
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t remaining_constituent_count;
	uint32_t i;
	struct ffa_partition_msg *retrieve_message = tx_buffer;
	bool not_specify_memory_type =
		share_func == FFA_MEM_DONATE_32 ||
		(share_func == FFA_MEM_LEND_32 && receivers_send_count == 1);
	uint64_t allocator_mask;
	bool contains_secure_receiver = false;

	/* Send the first fragment of the memory. */
	remaining_constituent_count = ffa_memory_region_init(
		tx_buffer, HF_MAILBOX_SIZE, sender, receivers_send,
		receivers_send_count, constituents, constituent_count, 0,
		send_flags,
		not_specify_memory_type ? FFA_MEMORY_NOT_SPECIFIED_MEM
					: FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
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

	/* Check if any of the receivers is a secure endpoint. */
	for (i = 0; i < receivers_send_count; i++) {
		if (!IS_VM_ID(
			    receivers_send[i].receiver_permissions.receiver)) {
			contains_secure_receiver = true;
			break;
		}
	}

	/*
	 * If the sender is a secure endpoint, or at least one of the
	 * receivers in a multi-endpoint memory sharing is a secure endpoint,
	 * the allocator will be the SPMC.
	 * Else, it will be the hypervisor.
	 */
	allocator_mask = (!IS_VM_ID(sender) || contains_secure_receiver)
				 ? FFA_MEMORY_HANDLE_ALLOCATOR_SPMC
				 : FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;

	send_fragmented_memory_region(
		&ret, tx_buffer, constituents, constituent_count,
		remaining_constituent_count, fragment_length, total_length,
		&handle, allocator_mask);

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		sender, receivers_retrieve, receivers_retrieve_count, 0,
		retrieve_flags, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);

	for (i = 0; i < receivers_send_count; i++) {
		struct ffa_memory_region_attributes *receiver =
			&(receivers_send[i].receiver_permissions);
		dlog_verbose(
			"Sending the retrieve request message to receiver: "
			"%x\n",
			receiver->receiver);

		/*
		 * Send the appropriate retrieve request to the VM so that it
		 * can use it to retrieve the memory.
		 */
		EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
		ffa_rxtx_header_init(sender, receiver->receiver, msg_size,
				     &retrieve_message->header);
		ASSERT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
	}

	return handle;
}

/*
 * Helper function to send memory to a VM then send a message with the retrieve
 * request it needs to retrieve it.
 */
ffa_memory_handle_t send_memory_and_retrieve_request(
	uint32_t share_func, void *tx_buffer, ffa_vm_id_t sender,
	ffa_vm_id_t recipient,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access)
{
	struct ffa_memory_access receiver_send_permissions;
	struct ffa_memory_access receiver_retrieve_permissions;

	ffa_memory_access_init_permissions(&receiver_send_permissions,
					   recipient, send_data_access,
					   send_instruction_access, 0);

	ffa_memory_access_init_permissions(&receiver_retrieve_permissions,
					   recipient, retrieve_data_access,
					   retrieve_instruction_access, 0);

	return send_memory_and_retrieve_request_multi_receiver(
		share_func, tx_buffer, sender, constituents, constituent_count,
		&receiver_send_permissions, 1, &receiver_retrieve_permissions,
		1, send_flags, retrieve_flags);
}

/*
 * Helper function to send memory to a VM then send a message with the retrieve
 * request it needs to retrieve it, forcing the request to be made in at least
 * two fragments even if it could fit in one.
 * TODO: check if it can be based off a base function like the above functions.
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
	struct ffa_partition_msg *retrieve_message;
	bool not_specify_memory_type = share_func == FFA_MEM_DONATE_32 ||
				       (share_func == FFA_MEM_LEND_32);

	/* Send everything except the last constituent in the first fragment. */
	remaining_constituent_count = ffa_memory_region_init_single_receiver(
		tx_buffer, HF_MAILBOX_SIZE, sender, recipient, constituents,
		constituent_count, 0, flags, send_data_access,
		send_instruction_access,
		not_specify_memory_type ? FFA_MEMORY_NOT_SPECIFIED_MEM
					: FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
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

	handle = ffa_frag_handle(ret);

	/* Send the last constituent in a separate fragment. */
	remaining_constituent_count = ffa_memory_fragment_init(
		tx_buffer, HF_MAILBOX_SIZE,
		&constituents[constituent_count - 1], 1, &fragment_length);
	EXPECT_EQ(remaining_constituent_count, 0);
	ret = ffa_mem_frag_tx(handle, fragment_length);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_success_handle(ret), handle);

	retrieve_message = (struct ffa_partition_msg *)tx_buffer;
	/*
	 * Send the appropriate retrieve request to the VM so that it can use it
	 */
	msg_size = ffa_memory_retrieve_request_init_single_receiver(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		sender, recipient, 0, flags, retrieve_data_access,
		retrieve_instruction_access, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);
	ffa_rxtx_header_init(sender, recipient, msg_size,
			     &retrieve_message->header);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	ASSERT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);

	return handle;
}

void send_retrieve_request_single_receiver(
	void *send, ffa_memory_handle_t handle, ffa_vm_id_t sender,
	ffa_vm_id_t receiver, uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability)
{
	struct ffa_memory_access receiver_retrieve_permissions;

	ffa_memory_access_init_permissions(&receiver_retrieve_permissions,
					   receiver, data_access,
					   instruction_access, 0);

	send_retrieve_request(send, handle, sender,
			      &receiver_retrieve_permissions, 1, tag, flags,
			      type, cacheability, shareability, receiver);
}

void send_retrieve_request(
	void *send, ffa_memory_handle_t handle, ffa_vm_id_t sender,
	struct ffa_memory_access receivers[], uint32_t receiver_count,
	uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, ffa_vm_id_t recipient)
{
	size_t msg_size;
	struct ffa_partition_msg *retrieve_message = send;

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		sender, receivers, receiver_count, tag, flags, type,
		cacheability, shareability);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ffa_rxtx_header_init(sender, recipient, msg_size,
			     &retrieve_message->header);

	ASSERT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
}

static struct ffa_partition_msg *get_mailbox_message(void *recv)
{
	ffa_vm_id_t sender;
	ffa_vm_id_t receiver;
	struct ffa_partition_msg *msg = (struct ffa_partition_msg *)recv;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_value ret =
		ffa_notification_get(own_id, 0,
				     FFA_NOTIFICATION_FLAG_BITMAP_HYP |
					     FFA_NOTIFICATION_FLAG_BITMAP_SPM);
	ffa_notifications_bitmap_t fwk_notif =
		ffa_notification_get_from_framework(ret);

	if (fwk_notif == 0U) {
		HFTEST_LOG("There is no framework notifications.");
		return NULL;
	}

	sender = ffa_rxtx_header_sender(&(msg->header));
	receiver = ffa_rxtx_header_receiver(&(msg->header));

	EXPECT_EQ(receiver, own_id);

	if (is_ffa_spm_buffer_full_notification(fwk_notif)) {
		EXPECT_FALSE(IS_VM_ID(sender));
	} else if (is_ffa_hyp_buffer_full_notification(fwk_notif)) {
		EXPECT_TRUE(IS_VM_ID(sender));
	}

	return msg;
}

/*
 * Use the retrieve request from the receive buffer to retrieve a memory region
 * which has been sent to us. Copies all the fragments into the provided buffer
 * if any, and checks that the total length of all fragments is no more than
 * `memory_region_max_size`. Returns the sender, and the handle via a return
 * parameter.
 */
ffa_vm_id_t retrieve_memory_from_message(
	void *recv_buf, void *send_buf, ffa_memory_handle_t *handle,
	struct ffa_memory_region *memory_region_ret,
	size_t memory_region_max_size)
{
	uint32_t msg_size;
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;
	ffa_vm_id_t sender;
	struct ffa_memory_region *retrieve_request;
	ffa_memory_handle_t retrieved_handle;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t fragment_offset;
	const struct ffa_partition_msg *retrv_message =
		get_mailbox_message(recv_buf);

	ASSERT_TRUE(retrv_message != NULL);

	sender = ffa_rxtx_header_sender(&retrv_message->header);
	msg_size = retrv_message->header.size;

	retrieve_request = (struct ffa_memory_region *)retrv_message->payload;

	retrieved_handle = retrieve_request->handle;
	if (handle != NULL) {
		*handle = retrieved_handle;
	}
	memcpy_s(send_buf, HF_MAILBOX_SIZE, retrv_message->payload, msg_size);

	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	ASSERT_EQ(ret.func, FFA_MEM_RETRIEVE_RESP_32);
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
	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Retrieve the remaining fragments. */
	fragment_offset = fragment_length;
	while (fragment_offset < total_length) {
		dlog_verbose("Calling again. frag offset: %x; total: %x\n",
			     fragment_offset, total_length);
		ret = ffa_mem_frag_rx(retrieved_handle, fragment_offset);
		EXPECT_EQ(ret.func, FFA_MEM_FRAG_TX_32);
		EXPECT_EQ(ffa_frag_handle(ret), retrieved_handle);
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
		ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
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
						     int32_t expected_error)
{
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_vm_id_t sender;
	struct ffa_memory_region *retrieve_request;
	const struct ffa_partition_msg *retrv_message =
		get_mailbox_message(recv_buf);

	ASSERT_TRUE(retrv_message != NULL);

	sender = ffa_rxtx_header_sender(&retrv_message->header);
	msg_size = retrv_message->header.size;

	retrieve_request = (struct ffa_memory_region *)retrv_message->payload;

	memcpy_s(send_buf, HF_MAILBOX_SIZE, retrieve_request, msg_size);
	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	EXPECT_FFA_ERROR(ret, expected_error);

	return sender;
}

ffa_vm_count_t get_ffa_partition_info(struct ffa_uuid *uuid,
				      struct ffa_partition_info *info,
				      size_t info_size, void *recv)
{
	struct ffa_value ret;
	struct ffa_partition_info *ret_info = recv;

	CHECK(uuid != NULL);
	CHECK(info != NULL);

	ffa_version(MAKE_FFA_VERSION(1, 1));

	ret = ffa_partition_info_get(uuid, 0);

	if (ffa_func_id(ret) != FFA_SUCCESS_32) {
		return 0;
	}

	if (ret.arg2 != 0) {
		size_t src_size = ret.arg2 * sizeof(struct ffa_partition_info);
		size_t dest_size =
			info_size * sizeof(struct ffa_partition_info);

		memcpy_s(info, dest_size, ret_info, src_size);
	}

	ffa_rx_release();

	return ret.arg2;
}

/**
 * Dump the boot information passed to the partition.
 */
void dump_boot_info(struct ffa_boot_info_header *boot_info_header)
{
	struct ffa_boot_info_desc *boot_info_desc;

	if (boot_info_header == NULL) {
		HFTEST_LOG("SP doesn't have boot arguments!\n");
		return;
	}

	HFTEST_LOG("SP boot info (%x):", (uintptr_t)boot_info_header);
	HFTEST_LOG("  Signature: %x", boot_info_header->signature);
	HFTEST_LOG("  Version: %x", boot_info_header->version);
	HFTEST_LOG("  Blob Size: %u", boot_info_header->info_blob_size);
	HFTEST_LOG("  Descriptor Size: %u", boot_info_header->desc_size);
	HFTEST_LOG("  Descriptor Count: %u", boot_info_header->desc_count);

	boot_info_desc = boot_info_header->boot_info;

	if (boot_info_desc == NULL) {
		dlog_error("Boot data arguments error...");
		return;
	}

	for (uint32_t i = 0; i < boot_info_header->desc_count; i++) {
		HFTEST_LOG("      Type: %u", boot_info_desc[i].type);
		HFTEST_LOG("      Flags:");
		HFTEST_LOG("        Name Format: %x",
			   ffa_boot_info_name_format(&boot_info_desc[i]));
		HFTEST_LOG("        Content Format: %x",
			   ffa_boot_info_content_format(&boot_info_desc[i]));
		HFTEST_LOG("      Size: %u", boot_info_desc[i].size);
		HFTEST_LOG("      Value: %x", boot_info_desc[i].content);
	}
}

/**
 * Retrieve the boot info descriptor related to the provided type and type ID.
 */
struct ffa_boot_info_desc *get_boot_info_desc(
	struct ffa_boot_info_header *boot_info_header, uint8_t type,
	uint8_t type_id)
{
	struct ffa_boot_info_desc *boot_info_desc;

	assert(boot_info_header != NULL);

	ASSERT_EQ(boot_info_header->signature, 0xFFAU);
	ASSERT_EQ(boot_info_header->version, 0x10001U);
	ASSERT_EQ(boot_info_header->desc_size,
		  sizeof(struct ffa_boot_info_desc));
	ASSERT_EQ((uintptr_t)boot_info_header + boot_info_header->desc_offset,
		  (uintptr_t)boot_info_header->boot_info);

	boot_info_desc = boot_info_header->boot_info;

	for (uint32_t i = 0; i < boot_info_header->desc_count; i++) {
		if (ffa_boot_info_type_id(&boot_info_desc[i]) == type_id &&
		    ffa_boot_info_type(&boot_info_desc[i]) == type) {
			return &boot_info_desc[i];
		}
	}

	return NULL;
}

struct ffa_value send_indirect_message(ffa_vm_id_t from, ffa_vm_id_t to,
				       void *send, const void *payload,
				       size_t payload_size, uint32_t send_flags)
{
	struct ffa_partition_msg *message = (struct ffa_partition_msg *)send;

	/* Initialize message header. */
	ffa_rxtx_header_init(from, to, payload_size, &message->header);

	/* Fill TX buffer with payload. */
	memcpy_s(message->payload, FFA_PARTITION_MSG_PAYLOAD_MAX, payload,
		 payload_size);

	/* Send the message. */
	return ffa_msg_send2(send_flags);
}
