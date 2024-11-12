/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "hf/arch/mmu.h"

#include "hf/check.h"
#include "hf/mm.h"
#include "hf/static_assert.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa_v1_0.h"

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

/**
 * Try to receive a message from the mailbox, blocking if necessary, and
 * retrying if interrupted.
 */
void mailbox_receive_retry(void *buffer, size_t buffer_size, void *recv,
			   struct ffa_partition_rxtx_header *header)
{
	const struct ffa_partition_msg *message;
	const uint32_t *payload;
	ffa_id_t sender;
	struct ffa_value ret;
	ffa_notifications_bitmap_t fwk_notif = 0U;
	const ffa_id_t own_id = hf_vm_get_id();

	ASSERT_LE(buffer_size, FFA_MSG_PAYLOAD_MAX);
	ASSERT_TRUE(header != NULL);
	ASSERT_TRUE(recv != NULL);

	/* Check notification and wait if not messages. */
	while (fwk_notif == 0U) {
		ret = ffa_notification_get(
			own_id, 0,
			FFA_NOTIFICATION_FLAG_BITMAP_SPM |
				FFA_NOTIFICATION_FLAG_BITMAP_HYP);
		if (ret.func == FFA_SUCCESS_32) {
			fwk_notif = ffa_notification_get_from_framework(ret);
		}

		if (fwk_notif == 0U) {
			ffa_msg_wait();
		}
	}

	message = (const struct ffa_partition_msg *)recv;
	memcpy_s(header, sizeof(*header), message,
		 sizeof(struct ffa_partition_rxtx_header));

	sender = ffa_rxtx_header_sender(header);

	if (is_ffa_hyp_buffer_full_notification(fwk_notif)) {
		EXPECT_TRUE(ffa_is_vm_id(sender));
	} else {
		FAIL("Unexpected message sender.\n");
	}

	/* Check receiver ID against own ID. */
	ASSERT_EQ(ffa_rxtx_header_receiver(header), own_id);
	ASSERT_LE(header->size, buffer_size);

	payload = (const uint32_t *)message->payload;

	/* Get message to free the RX buffer. */
	memcpy_s(buffer, buffer_size, payload, header->size);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
}

void send_fragmented_memory_region(
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
	uint32_t share_func, void *tx_buffer, ffa_id_t sender,
	struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, struct ffa_memory_access receivers_send[],
	uint32_t receivers_send_count,
	struct ffa_memory_access receivers_retrieve[],
	uint32_t receivers_retrieve_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags,
	enum ffa_memory_type send_memory_type,
	enum ffa_memory_type receive_memory_type,
	enum ffa_memory_cacheability send_cacheability,
	enum ffa_memory_cacheability receive_cacheability)
{
	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_memory_handle_t handle;
	uint32_t remaining_constituent_count;
	uint32_t i;
	struct ffa_partition_msg *retrieve_message = tx_buffer;
	uint64_t allocator_mask;
	bool contains_secure_receiver = false;

	/* Send the first fragment of the memory. */
	remaining_constituent_count = ffa_memory_region_init(
		tx_buffer, HF_MAILBOX_SIZE, sender, receivers_send,
		receivers_send_count, sizeof(struct ffa_memory_access),
		constituents, constituent_count, 0, send_flags,
		send_memory_type, send_cacheability, FFA_MEMORY_INNER_SHAREABLE,
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
		if (!ffa_is_vm_id(
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
	allocator_mask = (!ffa_is_vm_id(sender) || contains_secure_receiver)
				 ? FFA_MEMORY_HANDLE_ALLOCATOR_SPMC
				 : FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;

	send_fragmented_memory_region(
		&ret, tx_buffer, constituents, constituent_count,
		remaining_constituent_count, fragment_length, total_length,
		&handle, allocator_mask);

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		sender, receivers_retrieve, receivers_retrieve_count,
		sizeof(struct ffa_memory_access), 0, retrieve_flags,
		receive_memory_type, receive_cacheability,
		FFA_MEMORY_INNER_SHAREABLE);

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
	uint32_t share_func, void *tx_buffer, ffa_id_t sender,
	ffa_id_t recipient, struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, ffa_memory_region_flags_t send_flags,
	ffa_memory_region_flags_t retrieve_flags,
	enum ffa_data_access send_data_access,
	enum ffa_data_access retrieve_data_access,
	enum ffa_instruction_access send_instruction_access,
	enum ffa_instruction_access retrieve_instruction_access,
	enum ffa_memory_type send_memory_type,
	enum ffa_memory_type receive_memory_type,
	enum ffa_memory_cacheability send_cacheability,
	enum ffa_memory_cacheability receive_cacheability)
{
	struct ffa_memory_access receiver_send_permissions;
	struct ffa_memory_access receiver_retrieve_permissions;
	/*
	 * Use the sender id as the impdef value so we can use this in later
	 * testing.
	 */
	struct ffa_memory_access_impdef impdef_val =
		ffa_memory_access_impdef_init(sender, sender + 1);

	ffa_memory_access_init(&receiver_send_permissions, recipient,
			       send_data_access, send_instruction_access, 0,
			       &impdef_val);

	ffa_memory_access_init(&receiver_retrieve_permissions, recipient,
			       retrieve_data_access,
			       retrieve_instruction_access, 0, &impdef_val);

	return send_memory_and_retrieve_request_multi_receiver(
		share_func, tx_buffer, sender, constituents, constituent_count,
		&receiver_send_permissions, 1, &receiver_retrieve_permissions,
		1, send_flags, retrieve_flags, send_memory_type,
		receive_memory_type, send_cacheability, receive_cacheability);
}

/*
 * Helper function to send memory to a VM then send a message with the retrieve
 * request it needs to retrieve it, forcing the request to be made in at least
 * two fragments even if it could fit in one.
 * TODO: check if it can be based off a base function like the above functions.
 */
ffa_memory_handle_t send_memory_and_retrieve_request_force_fragmented(
	uint32_t share_func, void *tx_buffer, ffa_id_t sender,
	ffa_id_t recipient, struct ffa_memory_region_constituent constituents[],
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
	struct ffa_memory_access_impdef impdef_val =
		ffa_memory_access_impdef_init(sender, sender + 1);

	/* Send everything except the last constituent in the first fragment. */
	remaining_constituent_count = ffa_memory_region_init_single_receiver(
		tx_buffer, HF_MAILBOX_SIZE, sender, recipient, constituents,
		constituent_count, 0, flags, send_data_access,
		send_instruction_access,
		not_specify_memory_type ? FFA_MEMORY_NOT_SPECIFIED_MEM
					: FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&impdef_val, &total_length, &fragment_length);
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
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&impdef_val);
	ffa_rxtx_header_init(sender, recipient, msg_size,
			     &retrieve_message->header);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);
	ASSERT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);

	return handle;
}

void send_retrieve_request_single_receiver(
	void *send, ffa_memory_handle_t handle, ffa_id_t sender,
	ffa_id_t receiver, uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability,
	struct ffa_memory_access_impdef *impdef_val)
{
	struct ffa_memory_access receiver_retrieve_permissions;

	ffa_memory_access_init(&receiver_retrieve_permissions, receiver,
			       data_access, instruction_access, 0, impdef_val);

	send_retrieve_request(send, handle, sender,
			      &receiver_retrieve_permissions, 1, tag, flags,
			      type, cacheability, shareability, receiver);
}

void send_retrieve_request(
	void *send, ffa_memory_handle_t handle, ffa_id_t sender,
	struct ffa_memory_access receivers[], uint32_t receiver_count,
	uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, ffa_id_t recipient)
{
	size_t msg_size;
	struct ffa_partition_msg *retrieve_message = send;

	msg_size = ffa_memory_retrieve_request_init(
		(struct ffa_memory_region *)retrieve_message->payload, handle,
		sender, receivers, receiver_count,
		sizeof(struct ffa_memory_access), tag, flags, type,
		cacheability, shareability);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ffa_rxtx_header_init(sender, recipient, msg_size,
			     &retrieve_message->header);

	ASSERT_EQ(ffa_msg_send2(0).func, FFA_SUCCESS_32);
}

static struct ffa_partition_msg *get_mailbox_message(void *recv)
{
	ffa_id_t sender;
	ffa_id_t receiver;
	struct ffa_partition_msg *msg = (struct ffa_partition_msg *)recv;
	ffa_id_t own_id = hf_vm_get_id();
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
		EXPECT_FALSE(ffa_is_vm_id(sender));
	} else if (is_ffa_hyp_buffer_full_notification(fwk_notif)) {
		EXPECT_TRUE(ffa_is_vm_id(sender));
	}

	return msg;
}

/**
 * Retrieve a memory region descriptor from fragments in the rx buffer.
 * We keep building the memory region descriptor form the rx buffer until
 * the fragment offset matches the total length we expect.
 */
void memory_region_desc_from_rx_fragments(uint32_t fragment_length,
					  uint32_t total_length,
					  ffa_memory_handle_t handle,
					  void *memory_region, void *recv_buf,
					  uint32_t memory_region_max_size)
{
	struct ffa_value ret;
	uint32_t fragment_offset = fragment_length;

	while (fragment_offset < total_length) {
		ret = ffa_mem_frag_rx(handle, fragment_offset);
		EXPECT_EQ(ret.func, FFA_MEM_FRAG_TX_32);
		EXPECT_EQ(ffa_frag_handle(ret), handle);
		fragment_length = ret.arg3;
		EXPECT_GT(fragment_length, 0);
		ASSERT_LE(fragment_offset + fragment_length,
			  memory_region_max_size);
		/* Copy received fragment. */
		memcpy_s((uint8_t *)memory_region + fragment_offset,
			 memory_region_max_size - fragment_offset, recv_buf,
			 fragment_length);
		fragment_offset += fragment_length;
		ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	}
	EXPECT_EQ(fragment_offset, total_length);
}

/*
 * Retrieve a memory region from `recv_buf`. Copies all the fragments into
 * `memory_region_ret` if non-null, and checks that the total length of all
 * fragments is no more than `memory_region_max_size`.
 */
void retrieve_memory(void *recv_buf, ffa_memory_handle_t handle,
		     struct ffa_memory_region *memory_region_ret,
		     size_t memory_region_max_size, uint32_t msg_size)
{
	struct ffa_value ret;
	struct ffa_memory_region *memory_region;
	struct ffa_memory_access *receiver;
	uint32_t fragment_length;
	uint32_t total_length;
	ffa_id_t own_id = hf_vm_get_id();

	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	ASSERT_EQ(ret.func, FFA_MEM_RETRIEVE_RESP_32);
	total_length = ret.arg1;
	fragment_length = ret.arg2;
	EXPECT_GE(fragment_length,
		  sizeof(struct ffa_memory_region) +
			  sizeof(struct ffa_memory_access_v1_0) +
			  sizeof(struct ffa_composite_memory_region));
	EXPECT_LE(fragment_length, HF_MAILBOX_SIZE);
	EXPECT_LE(fragment_length, total_length);
	memory_region = (struct ffa_memory_region *)recv_buf;
	EXPECT_EQ(memory_region->receiver_count, 1);
	receiver = ffa_memory_region_get_receiver(memory_region, 0);
	EXPECT_TRUE(receiver != NULL);
	EXPECT_EQ(receiver->receiver_permissions.receiver, own_id);

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
	memory_region_desc_from_rx_fragments(fragment_length, total_length,
					     handle, memory_region_ret,
					     recv_buf, memory_region_max_size);
}

/*
 * Use the retrieve request from the receive buffer (`recv_buf`) to retrieve a
 * memory region which has been sent to us. Copies all the fragments into
 * `memory_region_ret` if non-null, and checks that the total length of all
 * fragments is no more than `memory_region_max_size`. Returns the sender, and
 * the handle via `ret_handle`
 */
ffa_id_t retrieve_memory_from_message(
	void *recv_buf, void *send_buf, ffa_memory_handle_t *ret_handle,
	struct ffa_memory_region *memory_region_ret,
	size_t memory_region_max_size)
{
	uint32_t msg_size;
	ffa_id_t sender;
	struct ffa_memory_region *retrieve_request;
	ffa_memory_handle_t retrieved_handle;
	const struct ffa_partition_msg *retrv_message =
		get_mailbox_message(recv_buf);
	ffa_id_t own_id = hf_vm_get_id();

	ASSERT_TRUE(retrv_message != NULL);

	sender = ffa_rxtx_header_sender(&retrv_message->header);
	msg_size = retrv_message->header.size;

	retrieve_request = (struct ffa_memory_region *)retrv_message->payload;

	retrieved_handle = retrieve_request->handle;
	if (ret_handle != NULL) {
		*ret_handle = retrieved_handle;
	}
	memcpy_s(send_buf, HF_MAILBOX_SIZE, retrv_message->payload, msg_size);

	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	retrieve_memory(recv_buf, retrieved_handle, memory_region_ret,
			memory_region_max_size, msg_size);

	/*
	 * If the sender is a VM, and the receiver is an SP the NS bit
	 * should be set in the retrieve response.
	 */
	if (!ffa_is_vm_id(own_id) && ffa_is_vm_id(sender) &&
	    memory_region_ret != NULL) {
		enum ffa_memory_security retrieved_security =
			memory_region_ret->attributes.security;

		EXPECT_EQ(retrieved_security, FFA_MEMORY_SECURITY_NON_SECURE);
	}

	return sender;
}

/*
 * Use the retrieve request from the receive buffer to retrieve a memory region
 * which has been sent to us, expecting it to fail with the given error code.
 * Returns the sender.
 */
ffa_id_t retrieve_memory_from_message_expect_fail(void *recv_buf,
						  void *send_buf,
						  enum ffa_error expected_error)
{
	uint32_t msg_size;
	struct ffa_value ret;
	ffa_id_t sender;
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

/**
 * Helper wrapper around `ffa_partition_info_get`.
 * Fills `infos` array with partition information and returns number of
 * partition infos written.
 */
ffa_vm_count_t get_ffa_partition_info(struct ffa_uuid uuid,
				      struct ffa_partition_info infos[],
				      size_t info_len, void *recv)
{
	struct ffa_value ret;
	struct ffa_partition_info *ret_info = recv;
	size_t ret_len;

	CHECK(infos != NULL);

	ret = ffa_partition_info_get(&uuid, 0);

	if (ffa_func_id(ret) != FFA_SUCCESS_32) {
		return 0;
	}

	ret_len = ret.arg2;
	if (ret_len != 0) {
		size_t src_size = ret_len * sizeof(struct ffa_partition_info);
		size_t dest_size = info_len * sizeof(struct ffa_partition_info);

		CHECK(info_len >= ret_len);

		memcpy_s(infos, dest_size, ret_info, src_size);
	}

	ffa_rx_release();

	return ret_len;
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

	HFTEST_LOG("SP boot info (%lx):", (uintptr_t)boot_info_header);
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
		HFTEST_LOG("      Value: %lx", boot_info_desc[i].content);
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
	ASSERT_GE(boot_info_header->version, 0x10001U);
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

struct ffa_value send_indirect_message(ffa_id_t from, ffa_id_t to, void *send,
				       const void *payload, size_t payload_size,
				       uint32_t send_flags)
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

void receive_indirect_message(void *buffer, size_t buffer_size, void *recv,
			      ffa_id_t *sender)
{
	const struct ffa_partition_msg *message;
	struct ffa_partition_rxtx_header header;
	ffa_id_t source_vm_id;
	const uint32_t *payload;
	struct ffa_value ret;
	ffa_notifications_bitmap_t fwk_notif;
	const ffa_id_t own_id = hf_vm_get_id();

	EXPECT_LE(buffer_size, FFA_MSG_PAYLOAD_MAX);

	/* Check notification */
	ret = ffa_notification_get(own_id, 0,
				   FFA_NOTIFICATION_FLAG_BITMAP_SPM |
					   FFA_NOTIFICATION_FLAG_BITMAP_HYP);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);

	fwk_notif = ffa_notification_get_from_framework(ret);

	if (fwk_notif == 0U) {
		FAIL("Expected Rx buffer full notification.");
	}

	message = (const struct ffa_partition_msg *)recv;
	memcpy_s(&header, sizeof(header), message,
		 sizeof(struct ffa_partition_rxtx_header));

	source_vm_id = ffa_rxtx_header_sender(&header);

	if (is_ffa_hyp_buffer_full_notification(fwk_notif)) {
		EXPECT_TRUE(ffa_is_vm_id(source_vm_id));
	} else if (is_ffa_spm_buffer_full_notification(fwk_notif)) {
		EXPECT_FALSE(ffa_is_vm_id(source_vm_id));
	}

	/* Check receiver ID against own ID. */
	ASSERT_EQ(ffa_rxtx_header_receiver(&header), own_id);
	ASSERT_LE(header.size, buffer_size);

	payload = (const uint32_t *)message->payload;

	/* Get message to free the RX buffer. */
	memcpy_s(buffer, buffer_size, payload, header.size);

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	if (sender != NULL) {
		*sender = source_vm_id;
	}
}

bool ffa_partition_info_regs_get_part_info(
	struct ffa_value args, uint8_t idx,
	struct ffa_partition_info *partition_info)
{
	/* list of pointers to args in return value */
	uint64_t *arg_ptrs[15] = {
		&args.arg3,
		&args.arg4,
		&args.arg5,
		&args.arg6,
		&args.arg7,
		&args.extended_val.arg8,
		&args.extended_val.arg9,
		&args.extended_val.arg10,
		&args.extended_val.arg11,
		&args.extended_val.arg12,
		&args.extended_val.arg13,
		&args.extended_val.arg14,
		&args.extended_val.arg15,
		&args.extended_val.arg16,
		&args.extended_val.arg17,
	};

	/*
	 * Each partition information is encoded in 3 registers, so there can be
	 * a maximum of 5 entries.
	 */
	if (idx >= 5 || !partition_info) {
		return false;
	}

	uint64_t info = *(arg_ptrs[(ptrdiff_t)(idx * 3)]);
	uint64_t uuid_lo = *(arg_ptrs[(ptrdiff_t)(idx * 3) + 1]);
	uint64_t uuid_high = *(arg_ptrs[(ptrdiff_t)(idx * 3) + 2]);

	partition_info->vm_id = info & 0xFFFF;
	partition_info->vcpu_count = (info >> 16) & 0xFFFF;
	partition_info->properties = (info >> 32);
	ffa_uuid_from_u64x2(uuid_lo, uuid_high, &partition_info->uuid);

	return true;
}

/*
 * Update security state on S1 page table based on attributes
 * set in the memory region structure.
 */
void update_mm_security_state(struct ffa_composite_memory_region *composite,
			      ffa_memory_attributes_t attributes)
{
	if (attributes.security == FFA_MEMORY_SECURITY_NON_SECURE &&
	    !ffa_is_vm_id(hf_vm_get_id())) {
		for (uint32_t i = 0; i < composite->constituent_count; i++) {
			uint32_t mode;

			if (!hftest_mm_get_mode(
				    // NOLINTNEXTLINE(performance-no-int-to-ptr)
				    (const void *)composite->constituents[i]
					    .address,
				    FFA_PAGE_SIZE * composite->constituents[i]
							    .page_count,
				    &mode)) {
				FAIL("Couldn't get the mode of the "
				     "composite.\n");
			}

			hftest_mm_identity_map(
				// NOLINTNEXTLINE(performance-no-int-to-ptr)
				(const void *)composite->constituents[i]
					.address,
				FFA_PAGE_SIZE *
					composite->constituents[i].page_count,
				mode | MM_MODE_NS);
		}
	}
}

/**
 * Call FFA_NOTIFICATION_INFO_GET and check the reponse with the values
 * expected.
 */
void ffa_notification_info_get_and_check(
	const uint32_t expected_lists_count,
	const uint32_t *const expected_lists_sizes,
	const uint16_t *const expected_ids)
{
	struct ffa_value ret = ffa_notification_info_get();

	EXPECT_EQ(ret.func, FFA_SUCCESS_64);
	EXPECT_EQ(ffa_notification_info_get_lists_count(ret),
		  expected_lists_count);

	for (uint32_t i = 0; i < expected_lists_count; i++) {
		EXPECT_EQ(ffa_notification_info_get_list_size(ret, i + 1),
			  expected_lists_sizes[i]);
	}

	EXPECT_EQ(memcmp(&ret.arg3, expected_ids,
			 sizeof(expected_ids[0] *
				FFA_NOTIFICATIONS_INFO_GET_MAX_IDS)),
		  0);
}

/**
 * Various tests rely on shared variables among endpoints for test
 * coordination. This utility is helpful for an endpoint to obtain
 * the address of a shared page that holds the common variables.
 */
uint64_t get_shared_page_from_message(void *recv_buf, void *send_buf,
				      void *retrieve_buffer)
{
	struct ffa_memory_region *memory_region =
		(struct ffa_memory_region *)retrieve_buffer;
	struct ffa_composite_memory_region *composite;

	retrieve_memory_from_message(recv_buf, send_buf, NULL, memory_region,
				     HF_MAILBOX_SIZE);
	composite = ffa_memory_region_get_composite(memory_region, 0);

	/* Expect memory is NS and needs to be updated. */
	update_mm_security_state(composite, memory_region->attributes);

	return composite->constituents[0].address;
}

/**
 * Share a normal write-back cacheable page with other endpoints in the test.
 * This page holds common variables used for test coordination. All receivers
 * have read write permissions to the shared page.
 */
void share_page_with_endpoints(uint64_t page, ffa_id_t receivers_ids[],
			       size_t receivers_count, void *send_buf)
{
	struct ffa_memory_region_constituent constituents[] = {
		{.address = page, .page_count = 1},
	};
	struct ffa_memory_access receivers[2];

	/* Currently tests don't need more than two. */
	assert(receivers_count <= 2);

	/* Provide same level of access to the receivers. */
	for (size_t i = 0; i < receivers_count; i++) {
		ffa_memory_access_init(
			&receivers[i], receivers_ids[i], FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, NULL);
	}

	send_memory_and_retrieve_request_multi_receiver(
		FFA_MEM_SHARE_32, send_buf, HF_PRIMARY_VM_ID, constituents,
		ARRAY_SIZE(constituents), receivers, receivers_count, receivers,
		receivers_count, 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_CACHE_WRITE_BACK);
}
