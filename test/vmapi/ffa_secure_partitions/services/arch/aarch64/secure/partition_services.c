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

struct ffa_value sp_echo_cmd(ffa_id_t receiver, uint32_t val1, uint32_t val2,
			     uint32_t val3, uint32_t val4, uint32_t val5)
{
	ffa_id_t own_id = hf_vm_get_id();
	return ffa_msg_send_direct_resp(own_id, receiver, val1, val2, val3,
					val4, val5);
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

static uint8_t retrieve_buffer[PAGE_SIZE * 2];

static struct ffa_value retrieve_v1_0(ffa_id_t sender_id,
				      ffa_memory_handle_t handle)
{
	ffa_id_t receiver_id = hf_vm_get_id();
	void *rx_buffer = SERVICE_RECV_BUFFER();
	void *tx_buffer = SERVICE_SEND_BUFFER();
	struct ffa_memory_access_v1_0 receiver_v1_0;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region_v1_0 *memory_region_v1_0 =
		(struct ffa_memory_region_v1_0 *)retrieve_buffer;
	uint8_t *ptr;
	struct ffa_value ret;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t msg_size;
	uint32_t memory_region_max_size = HF_MAILBOX_SIZE;

	ffa_memory_access_init_v1_0(&receiver_v1_0, receiver_id,
				    FFA_DATA_ACCESS_RW,
				    FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0);
	msg_size = ffa_memory_retrieve_request_init_v1_0(
		tx_buffer, handle, sender_id, &receiver_v1_0, 1, 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE, FFA_MEMORY_NORMAL_MEM,
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

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;
	for (uint32_t i = 0; i < PAGE_SIZE; ++i) {
		++ptr[i];
	}

	/* Retrieved all the fragments. */
	return sp_success(receiver_id, sender_id, ret.func);
}

static struct ffa_value retrieve_v1_2_or_later(ffa_id_t sender_id,
					       ffa_memory_handle_t handle)
{
	ffa_id_t receiver_id = hf_vm_get_id();
	void *rx_buffer = SERVICE_RECV_BUFFER();
	void *tx_buffer = SERVICE_SEND_BUFFER();
	struct ffa_memory_access receiver_v1_1;
	struct ffa_composite_memory_region *composite;
	struct ffa_memory_region *memory_region_v1_1 =
		(struct ffa_memory_region *)retrieve_buffer;
	uint8_t *ptr;
	struct ffa_value ret;
	uint32_t fragment_length;
	uint32_t total_length;
	uint32_t msg_size;
	uint32_t memory_region_max_size = HF_MAILBOX_SIZE;

	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(receiver_id, receiver_id + 1);
	ffa_memory_access_init(&receiver_v1_1, receiver_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);
	msg_size = ffa_memory_retrieve_request_init(
		tx_buffer, handle, sender_id, &receiver_v1_1, 1,
		sizeof(struct ffa_memory_access), 0,
		FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE);

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

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	ptr = (uint8_t *)composite->constituents[0].address;
	for (uint32_t i = 0; i < PAGE_SIZE; ++i) {
		++ptr[i];
	}

	/* Retrieved all the fragments. */
	return sp_success(receiver_id, sender_id, ret.func);
}

struct ffa_value sp_ffa_mem_retrieve_cmd(ffa_id_t sender_id,
					 ffa_memory_handle_t handle,
					 enum ffa_version ffa_version)
{
	switch (ffa_version) {
	case FFA_VERSION_1_0:
		return retrieve_v1_0(sender_id, handle);
	case FFA_VERSION_1_1:
	case FFA_VERSION_1_2:
		return retrieve_v1_2_or_later(sender_id, handle);
	}
	panic("Unknown version %#x\n", ffa_version);
}
