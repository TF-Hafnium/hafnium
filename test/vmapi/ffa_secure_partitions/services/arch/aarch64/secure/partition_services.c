/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "partition_services.h"

#include "hf/arch/irq.h"
#include "hf/arch/mmu.h"
#include "hf/arch/types.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/ffa.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa_v1_0.h"

#include "../smc.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

uint64_t shared_nwd_buffer_addr;
static ffa_memory_handle_t shared_nwd_buffer_handle;

/* Page count this SP last registered its RX/TX mailbox with. */
static uint32_t sp_mailbox_page_count = 1;

struct ffa_value sp_echo_cmd(ffa_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5)
{
	ffa_id_t own_id = hf_vm_get_id();
	return ffa_msg_send_direct_resp(own_id, receiver, val1, val2, val3,
					val4, val5);
}

struct ffa_value sp_remap_mailbox_cmd(ffa_id_t receiver, uint32_t page_count)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct hftest_context *ctx = hftest_get_context();
	struct mailbox_buffers mb;

	/*
	 * Drop the mailbox the SP registered at boot and re-register one of
	 * the requested size, so the test can give this endpoint a mailbox
	 * size that differs from other endpoints in the same SPMC.
	 */
	if (ffa_rxtx_unmap().func != FFA_SUCCESS_32) {
		return sp_error(own_id, receiver, FFA_DENIED);
	}

	mb = set_up_mailbox_pages(page_count);
	ctx->send = mb.send;
	ctx->recv = mb.recv;
	sp_mailbox_page_count = page_count;

	return sp_success(own_id, receiver, page_count);
}

struct ffa_value sp_check_partition_info_rx_cmd(ffa_id_t receiver)
{
	ffa_id_t own_id = hf_vm_get_id();
	uint8_t *rx = SERVICE_RECV_BUFFER();
	const size_t rx_size = (size_t)sp_mailbox_page_count * FFA_PAGE_SIZE;
	const uint8_t sentinel = 0xA5;
	struct ffa_uuid uuid;
	struct ffa_value ret;
	size_t descriptor_bytes;

	/* Pre-paint the whole RX so we can spot any over-copy. */
	memset_s(rx, rx_size, sentinel, rx_size);

	ffa_uuid_init(0, 0, 0, 0, &uuid);
	ret = ffa_partition_info_get(&uuid, 0);
	if (ret.func != FFA_SUCCESS_32) {
		return sp_error(own_id, receiver, ffa_error_code(ret));
	}

	/* Bytes past the descriptor table must have been zeroed (4.10). */
	descriptor_bytes = (size_t)ret.arg2 * (size_t)ret.arg3;
	if (descriptor_bytes > rx_size) {
		ffa_rx_release();
		return sp_error(own_id, receiver, FFA_INVALID_PARAMETERS);
	}
	for (size_t i = descriptor_bytes; i < rx_size; i++) {
		if (rx[i] != 0) {
			ffa_rx_release();
			return sp_error(own_id, receiver,
					FFA_INVALID_PARAMETERS);
		}
	}

	ffa_rx_release();
	return sp_success(own_id, receiver, ret.arg2);
}

/*
 * Retrieve `handle` into this SP's RX and return the response's
 * `fragment_length`, or SIZE_MAX if the retrieve itself failed. Builds the
 * retrieve request in whichever descriptor format matches this SP's own
 * negotiated FF-A version.
 */
static size_t retrieve_into_rx(ffa_id_t own_id, ffa_memory_handle_t handle,
			       ffa_id_t mem_sender)
{
	void *tx = SERVICE_SEND_BUFFER();
	struct ffa_value ret;
	uint32_t msg_size;
	enum ffa_version ffa_version =
		hftest_get_context()->partition_manifest.ffa_version;

	if (ffa_version == FFA_VERSION_1_0) {
		struct ffa_memory_access_v1_0 receiver_acc_v1_0;

		ffa_memory_access_init_v1_0(
			&receiver_acc_v1_0, own_id, FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, 0);
		msg_size = ffa_memory_retrieve_request_init_v1_0(
			tx, handle, mem_sender, &receiver_acc_v1_0, 1, 0,
			FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE);
	} else {
		struct ffa_memory_access receiver_acc;
		struct ffa_memory_access_impdef impdef =
			ffa_memory_access_impdef_init(own_id, own_id + 1);

		ffa_memory_access_init(
			&receiver_acc, own_id, FFA_DATA_ACCESS_RW,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0, &impdef);
		msg_size = ffa_memory_retrieve_request_init(
			tx, handle, mem_sender, &receiver_acc, 1,
			sizeof(struct ffa_memory_access), 0,
			FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE,
			FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			FFA_MEMORY_INNER_SHAREABLE);
	}

	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	if (ret.func != FFA_MEM_RETRIEVE_RESP_32) {
		return SIZE_MAX;
	}

	return ret.arg2;
}

/*
 * Verify that the SPMC zeros the unpopulated tail of this SP's RX buffer
 * after writing a memory retrieve response (FF-A v1.3 section 4.10).
 *
 * This SP's RX buffer is mapped read-only to it (the SPMC is the producer
 * that writes into it), so it can't pre-paint its own RX with a sentinel to
 * detect stale bytes. Instead, `filler_handle` (a region large enough that
 * its retrieve response spans more than one FF-A page of non-zero
 * descriptor bytes, well past where the real response below ends) is
 * retrieved first to legitimately dirty the buffer. `real_handle` (a
 * smaller region) is then retrieved, and every byte past its response must
 * have been cleared by the SPMC even though the filler retrieve just wrote
 * non-zero content there.
 */
struct ffa_value sp_check_retrieve_rx_tail_cmd(
	ffa_id_t receiver, ffa_id_t mem_sender,
	ffa_memory_handle_t filler_handle, ffa_memory_handle_t real_handle)
{
	ffa_id_t own_id = hf_vm_get_id();
	const uint8_t *rx = SERVICE_RECV_BUFFER();
	const size_t rx_size = (size_t)sp_mailbox_page_count * FFA_PAGE_SIZE;
	size_t fragment_length;

	fragment_length = retrieve_into_rx(own_id, filler_handle, mem_sender);
	if (fragment_length == SIZE_MAX) {
		return sp_error(own_id, receiver, FFA_INVALID_PARAMETERS);
	}
	ffa_rx_release();

	fragment_length = retrieve_into_rx(own_id, real_handle, mem_sender);
	if (fragment_length == SIZE_MAX) {
		return sp_error(own_id, receiver, FFA_INVALID_PARAMETERS);
	}

	/* Bytes past the retrieve response must have been zeroed (§4.10). */
	for (size_t i = fragment_length; i < rx_size; i++) {
		if (rx[i] != 0) {
			ffa_rx_release();
			return sp_error(own_id, receiver,
					FFA_INVALID_PARAMETERS);
		}
	}

	ffa_rx_release();
	return sp_success(own_id, receiver, 0);
}

struct ffa_value sp_req_echo_cmd(ffa_id_t test_source, uint32_t val1,
				 uint32_t val2, uint32_t val3, uint32_t val4)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = sp_echo_cmd_send(own_id, own_id + 1, val1, val2, val3, val4);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, val1);
	EXPECT_EQ(res.arg5, val2);
	EXPECT_EQ(res.arg6, val3);
	EXPECT_EQ(res.arg7, val4);

	return sp_success(own_id, test_source, 0);
}

struct ffa_value sp_req_echo_busy_cmd(ffa_id_t test_source)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	if (!ffa_is_vm_id(test_source)) {
		res = ffa_msg_send_direct_req(own_id, test_source, 0, 0, 0, 0,
					      0);
		EXPECT_FFA_ERROR(res, FFA_BUSY);
	} else {
		res = sp_req_echo_busy_cmd_send(own_id, own_id + 1);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	}

	return sp_success(own_id, test_source, 0);
}

/**
 * This test illustrates the checks performed by the RTM_FFA_DIR_REQ partition
 * runtime model for various transitions requested by SP through invocation of
 * FFA ABIs.
 */
struct ffa_value sp_check_state_transitions_cmd(ffa_id_t test_source,
						ffa_id_t companion_sp_id)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	/*
	 * The invocation of FFA_MSG_SEND_DIRECT_REQ under RTM_FFA_DIR_REQ is
	 * already part of the `succeeds_sp_to_sp_echo` test belonging to the
	 * `ffa_msg_send_direct_req` testsuite.
	 */

	/*
	 * Test invocation of FFA_MSG_SEND_DIRECT_RESP to an endpoint other
	 * than the one that allocated CPU cycles.
	 */
	res = ffa_msg_send_direct_resp(own_id, companion_sp_id, 0, 0, 0, 0, 0);
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	/* Test invocation of FFA_MSG_WAIT. */
	res = ffa_msg_wait();
	EXPECT_FFA_ERROR(res, FFA_DENIED);

	/* TODO: test the invocation of FFA_RUN ABI.*/
	/* Perform legal invocation of FFA_MSG_SEND_DIRECT_RESP. */
	return sp_success(own_id, test_source, 0);
}

/**
 * Using an SiP call, this helper utility can pend an interrupt. Useful for
 * testing purposes.
 */
struct ffa_value sp_trigger_espi_cmd(ffa_id_t source, uint32_t espi_id)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	/*
	 * The SiP function ID, 0x82000100, must have been added to the SMC
	 * whitelist of the SP that invokes it.
	 */
	res = smc32(0x82000100, espi_id, 0, 0, 0, 0, 0, 0);

	if ((int64_t)res.func == SMCCC_ERROR_UNKNOWN) {
		HFTEST_LOG("SiP SMC call not supported");
		sp_error(own_id, source, 0);
	}

	return sp_success(own_id, source, 0);
}

struct ffa_value sp_ffa_features_cmd(ffa_id_t source, uint32_t feature_func_id)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();

	res = ffa_call((struct ffa_value){
		.func = FFA_FEATURES_32,
		.arg1 = feature_func_id,
	});
	return ffa_msg_send_direct_resp(own_id, source, res.func, res.arg2, 0,
					0, 0);
}

/*
 * Sized to the build's mailbox capacity (not just two pages) so a retrieve
 * response as large as the caller's own multi-page RX buffer fits without
 * overflowing this staging area.
 */
alignas(PAGE_SIZE) static uint8_t retrieve_buffer[HF_MAILBOX_SIZE];

static struct ffa_value retrieve_v1_0(
	ffa_id_t sender_id, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t transaction_type,
	enum ffa_instruction_access instruction_access)
{
	ffa_id_t receiver_id = hf_vm_get_id();
	void *rx_buffer = SERVICE_RECV_BUFFER();
	void *tx_buffer = SERVICE_SEND_BUFFER();
	struct ffa_memory_access_v1_0 receiver_v1_0;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region_v1_0 *memory_region_v1_0 =
		(struct ffa_memory_region_v1_0 *)retrieve_buffer;
	struct ffa_value ret;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t msg_size;
	uint32_t memory_region_max_size = HF_MAILBOX_SIZE;

	ffa_memory_access_init_v1_0(&receiver_v1_0, receiver_id,
				    FFA_DATA_ACCESS_RW, instruction_access, 0,
				    0);
	msg_size = ffa_memory_retrieve_request_init_v1_0(
		tx_buffer, handle, sender_id, &receiver_v1_0, 1, 0,
		transaction_type, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);
	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_MEM_RETRIEVE_RESP_32);
	fragment_length = ret.arg2;
	total_length = ret.arg1;

	memcpy_s(memory_region_v1_0, memory_region_max_size, rx_buffer,
		 fragment_length);

	/* Copy first fragment. */
	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	memory_region_desc_from_rx_fragments(
		fragment_length, total_length, memory_region_v1_0->handle,
		memory_region_v1_0, rx_buffer, memory_region_max_size);
	composite = ffa_memory_region_get_composite_v1_0(memory_region_v1_0, 0);
	update_mm_security_state(
		composite,
		ffa_memory_attributes_extend(memory_region_v1_0->attributes));

	shared_nwd_buffer_addr = composite->constituents[0].address;
	shared_nwd_buffer_handle = memory_region_v1_0->handle;

	/* Retrieved all the fragments. */
	return sp_success(receiver_id, sender_id, ret.func);
}

static struct ffa_value retrieve_v1_2_or_later(
	ffa_id_t sender_id, ffa_memory_handle_t handle,
	ffa_memory_region_flags_t transaction_type,
	enum ffa_instruction_access instruction_access)
{
	ffa_id_t receiver_id = hf_vm_get_id();
	void *rx_buffer = SERVICE_RECV_BUFFER();
	void *tx_buffer = SERVICE_SEND_BUFFER();
	struct ffa_memory_access receiver_v1_1;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region *memory_region_v1_1 =
		(struct ffa_memory_region *)retrieve_buffer;
	struct ffa_value ret;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t msg_size;
	uint32_t memory_region_max_size = HF_MAILBOX_SIZE;

	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(receiver_id, receiver_id + 1);
	ffa_memory_access_init(&receiver_v1_1, receiver_id, FFA_DATA_ACCESS_RW,
			       instruction_access, 0, &impdef);
	msg_size = ffa_memory_retrieve_request_init(
		tx_buffer, handle, sender_id, &receiver_v1_1, 1,
		sizeof(struct ffa_memory_access), 0, transaction_type,
		FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
		FFA_MEMORY_INNER_SHAREABLE);

	EXPECT_LE(msg_size, HF_MAILBOX_SIZE);

	ret = ffa_mem_retrieve_req(msg_size, msg_size);
	EXPECT_EQ(ret.func, FFA_MEM_RETRIEVE_RESP_32);
	fragment_length = ret.arg2;
	total_length = ret.arg1;

	memcpy_s(memory_region_v1_1, memory_region_max_size, rx_buffer,
		 fragment_length);

	/* Copy first fragment. */
	ASSERT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	memory_region_desc_from_rx_fragments(
		fragment_length, total_length, memory_region_v1_1->handle,
		memory_region_v1_1, rx_buffer, memory_region_max_size);
	composite = ffa_memory_region_get_composite(memory_region_v1_1, 0);
	update_mm_security_state(composite, memory_region_v1_1->attributes);

	shared_nwd_buffer_addr = composite->constituents[0].address;
	shared_nwd_buffer_handle = memory_region_v1_1->handle;

	/*
	 * Retrieved all the fragments. Report the length of the first
	 * fragment so callers can check whether the whole response arrived
	 * in a single fragment (fragment_length == total_length), rather
	 * than assuming it did just because
	 * memory_region_desc_from_rx_fragments() transparently fetched any
	 * continuation fragments above.
	 */
	return ffa_msg_send_direct_resp(receiver_id, sender_id, SP_SUCCESS,
					ret.func, fragment_length, 0, 0);
}

struct ffa_value sp_ffa_mem_retrieve_cmd(ffa_id_t sender_id,
					 ffa_memory_handle_t handle,
					 enum ffa_version ffa_version)
{
	switch (ffa_version) {
	case FFA_VERSION_1_0:
		return retrieve_v1_0(sender_id, handle,
				     FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE,
				     FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED);
	case FFA_VERSION_1_1:
	case FFA_VERSION_1_2:
	case FFA_VERSION_1_3:
		return retrieve_v1_2_or_later(
			sender_id, handle,
			FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE,
			FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED);
	}
	panic("Unknown version %#x\n", ffa_version);
}

struct ffa_value sp_ffa_mem_lend_retrieve_cmd(ffa_id_t sender_id,
					      ffa_memory_handle_t handle)
{
	enum ffa_version ffa_version =
		hftest_get_context()->partition_manifest.ffa_version;

	switch (ffa_version) {
	case FFA_VERSION_1_0:
		return retrieve_v1_0(sender_id, handle,
				     FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND,
				     FFA_INSTRUCTION_ACCESS_NX);
	default:
		break;
	}

	return retrieve_v1_2_or_later(sender_id, handle,
				      FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND,
				      FFA_INSTRUCTION_ACCESS_NX);
}

struct ffa_value sp_increment_shared_buffer_cmd(ffa_id_t sender_id)
{
	ffa_id_t own_id = hf_vm_get_id();
	uint8_t *ptr;

	if (shared_nwd_buffer_addr == 0U) {
		dlog_error("Shared buffer not found\n");
		return sp_error(own_id, sender_id, 0);
	}

	hftest_mm_identity_map(
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(const void *)shared_nwd_buffer_addr, FFA_PAGE_SIZE,
		MM_MODE_NS | MM_MODE_R | MM_MODE_W);

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)shared_nwd_buffer_addr;

	for (uint32_t i = 0; i < PAGE_SIZE; ++i) {
		++ptr[i];
	}
	dlog("shared access at %lx\n", shared_nwd_buffer_addr);

	return sp_success(own_id, sender_id, 0);
}

struct ffa_value sp_relinquish_shared_buffer_cmd(ffa_id_t sender_id)
{
	ffa_id_t own_id = hf_vm_get_id();
	void *tx_buffer = SERVICE_SEND_BUFFER();

	ffa_mem_relinquish_init(tx_buffer, shared_nwd_buffer_handle, 0, own_id);
	EXPECT_EQ(ffa_mem_relinquish().func, FFA_SUCCESS_32);

	shared_nwd_buffer_addr = 0U;
	shared_nwd_buffer_handle = 0U;

	return sp_success(own_id, sender_id, 0);
}
