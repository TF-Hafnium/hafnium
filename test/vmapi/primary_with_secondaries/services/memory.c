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

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "hftest.h"
#include "primary_with_secondary.h"
#include "util.h"

alignas(PAGE_SIZE) static uint8_t page[PAGE_SIZE];

TEST_SERVICE(memory_increment)
{
	/* Loop, writing message to the shared memory. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		size_t i;

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);

		/* Check the memory was cleared. */
		void *recv_buf = SERVICE_RECV_BUFFER();
		ptr = *(uint8_t **)recv_buf;

		for (int i = 0; i < PAGE_SIZE; ++i) {
			ASSERT_EQ(ptr[i], 0);
		}

		/* Allow the memory to be populated. */
		EXPECT_EQ(spci_yield().func, SPCI_SUCCESS_32);

		/* Increment each byte of memory. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			++ptr[i];
		}

		/* Signal completion and reset. */
		spci_rx_release();
		spci_msg_send(hf_vm_get_id(), spci_msg_send_sender(ret),
			      sizeof(ptr), 0);
	}
}

TEST_SERVICE(memory_lend_relinquish_spci)
{
	/* Loop, giving memory back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		ptr = (uint8_t *)constituents[0].address;
		/* Relevant information read, mailbox can be cleared. */
		spci_rx_release();

		/* Check that one has access to the shared region. */
		for (int i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		spci_rx_release();
		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_relinquish_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0);
		spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY);

		/*
		 * Try and access the memory which will cause a fault unless the
		 * memory has been shared back again.
		 */
		ptr[0] = 123;
	}
}

TEST_SERVICE(memory_return)
{
	/* Loop, giving memory back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);

		/* Check the memory was cleared. */
		void *recv_buf = SERVICE_RECV_BUFFER();
		ptr = *(uint8_t **)recv_buf;

		for (int i = 0; i < PAGE_SIZE; ++i) {
			ASSERT_EQ(ptr[i], 0);
		}

		/* Give the memory back and notify the sender. */
		ASSERT_EQ(hf_share_memory(spci_msg_send_sender(ret),
					  (hf_ipaddr_t)ptr, PAGE_SIZE,
					  HF_MEMORY_GIVE),
			  0);
		spci_rx_release();
		spci_msg_send(hf_vm_get_id(), spci_msg_send_sender(ret),
			      sizeof(ptr), 0);

		/*
		 * Try and access the memory which will cause a fault unless the
		 * memory has been shared back again.
		 */
		ptr[0] = 123;
	}
}

TEST_SERVICE(give_memory_and_fault)
{
	uint8_t *ptr = page;

	/* Give memory to the primary. */
	ASSERT_EQ(hf_share_memory(HF_PRIMARY_VM_ID, (hf_ipaddr_t)&page,
				  PAGE_SIZE, HF_MEMORY_GIVE),
		  0);

	/*
	 * TODO: the address of the memory will be part of the proper API. That
	 *       API is still to be agreed on so the address is passed
	 *       explicitly to test the mechanism.
	 */
	memcpy_s(SERVICE_SEND_BUFFER(), SPCI_MSG_PAYLOAD_MAX, &ptr,
		 sizeof(ptr));
	EXPECT_EQ(
		spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(ptr), 0)
			.func,
		SPCI_SUCCESS_32);

	/* Try using the memory that isn't valid unless it's been returned. */
	page[16] = 123;
}

TEST_SERVICE(lend_memory_and_fault)
{
	uint8_t *ptr = page;

	/* Lend memory to the primary. */
	ASSERT_EQ(hf_share_memory(HF_PRIMARY_VM_ID, (hf_ipaddr_t)&page,
				  PAGE_SIZE, HF_MEMORY_LEND),
		  0);

	/*
	 * TODO: the address of the memory will be part of the proper API. That
	 *       API is still to be agreed on so the address is passed
	 *       explicitly to test the mechanism.
	 */
	memcpy_s(SERVICE_SEND_BUFFER(), SPCI_MSG_PAYLOAD_MAX, &ptr,
		 sizeof(ptr));
	EXPECT_EQ(
		spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(ptr), 0)
			.func,
		SPCI_SUCCESS_32);

	/* Try using the memory that isn't valid unless it's been returned. */
	page[633] = 180;
}

TEST_SERVICE(spci_memory_return)
{
	/* Loop, giving memory back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);
		spci_rx_release();

		ptr = (uint8_t *)constituents[0].address;

		/* Check that one has access to the shared region. */
		for (int i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_donate_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
			SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY);

		/*
		 * Try and access the memory which will cause a fault unless the
		 * memory has been shared back again.
		 */
		ptr[0] = 123;
	}
}

TEST_SERVICE(spci_donate_check_upper_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	ptr = (uint8_t *)constituents[0].address;

	/* Check that one cannot access out of bounds after donated region. */
	ptr[PAGE_SIZE]++;
}

TEST_SERVICE(spci_donate_check_lower_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	ptr = (uint8_t *)constituents[0].address;

	/* Check that one cannot access out of bounds before donated region. */
	ptr[-1]++;
}

/**
 * SPCI: Attempt to donate memory and then modify.
 */
TEST_SERVICE(spci_donate_secondary_and_fault)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint32_t msg_size;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	ptr = (uint8_t *)constituents[0].address;

	/* Donate memory to next VM. */
	msg_size = spci_memory_donate_init(
		send_buf, SERVICE_VM1, constituents,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret), SERVICE_VM1,
				msg_size, SPCI_MSG_SEND_LEGACY_MEMORY)
			  .func,
		  SPCI_SUCCESS_32);

	/* Ensure that we are unable to modify memory any more. */
	ptr[0] = 'c';
	EXPECT_EQ(ptr[0], 'c');
	spci_yield();
}

/**
 * SPCI: Attempt to donate memory twice from VM.
 */
TEST_SERVICE(spci_donate_twice)
{
	uint32_t msg_size;
	struct spci_value ret = spci_msg_wait();
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent constituent =
		spci_memory_region_get_constituents(memory_region)[0];

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	/* Yield to allow attempt to re donate from primary. */
	spci_yield();

	/* Give the memory back and notify the sender. */
	msg_size = spci_memory_donate_init(
		send_buf, HF_PRIMARY_VM_ID, &constituent,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(SERVICE_VM0, HF_PRIMARY_VM_ID, msg_size,
				SPCI_MSG_SEND_LEGACY_MEMORY)
			  .func,
		  SPCI_SUCCESS_32);

	/* Attempt to donate the memory to another VM. */
	msg_size = spci_memory_donate_init(
		send_buf, SERVICE_VM1, &constituent,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(
		spci_msg_send(spci_msg_send_receiver(ret), SERVICE_VM1,
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY),
		SPCI_INVALID_PARAMETERS);

	spci_yield();
}

/**
 * SPCI: Continually receive memory, check if we have access
 * and ensure it is not changed by a third party.
 */
TEST_SERVICE(spci_memory_receive)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		void *recv_buf = SERVICE_RECV_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);
		spci_rx_release();

		ptr = (uint8_t *)constituents[0].address;
		ptr[0] = 'd';
		spci_yield();

		/* Ensure memory has not changed. */
		EXPECT_EQ(ptr[0], 'd');
		spci_yield();
	}
}

/**
 * SPCI: Receive memory and attempt to donate from primary VM.
 */
TEST_SERVICE(spci_donate_invalid_source)
{
	uint32_t msg_size;
	struct spci_value ret = spci_msg_wait();
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	/* Give the memory back and notify the sender. */
	msg_size = spci_memory_donate_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
				msg_size, SPCI_MSG_SEND_LEGACY_MEMORY)
			  .func,
		  SPCI_SUCCESS_32);

	/* Fail to donate the memory from the primary to VM1. */
	msg_size = spci_memory_donate_init(
		send_buf, SERVICE_VM1, constituents,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY),
			  SPCI_INVALID_PARAMETERS);
	spci_yield();
}

TEST_SERVICE(spci_memory_lend_relinquish)
{
	/* Loop, giving memory back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);
		ptr = (uint8_t *)constituents[0].address;
		/* Relevant information read, mailbox can be cleared. */
		spci_rx_release();

		/* Check that one has access to the shared region. */
		for (int i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		spci_rx_release();
		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_relinquish_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0);
		spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY);

		/*
		 * Try and access the memory which will cause a fault unless the
		 * memory has been shared back again.
		 */
		ptr[0] = 123;
	}
}

/**
 * SPCI: Ensure that we can't relinquish donated memory.
 */
TEST_SERVICE(spci_memory_donate_relinquish)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);
		spci_rx_release();

		ptr = (uint8_t *)constituents[0].address;

		/* Check that one has access to the shared region. */
		for (int i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}
		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_relinquish_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0);
		EXPECT_SPCI_ERROR(spci_msg_send(spci_msg_send_receiver(ret),
						HF_PRIMARY_VM_ID, msg_size,
						SPCI_MSG_SEND_LEGACY_MEMORY),
				  SPCI_INVALID_PARAMETERS);

		/* Ensure we still have access to the memory. */
		ptr[0] = 123;

		spci_yield();
	}
}

/**
 * SPCI: Receive memory and attempt to donate from primary VM.
 */
TEST_SERVICE(spci_lend_invalid_source)
{
	uint32_t msg_size;
	struct spci_value ret = spci_msg_wait();

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	/* Attempt to relinquish from primary VM. */
	msg_size = spci_memory_relinquish_init(
		send_buf, spci_msg_send_receiver(ret), constituents,
		memory_region->constituent_count, 0);
	EXPECT_SPCI_ERROR(
		spci_msg_send(HF_PRIMARY_VM_ID, spci_msg_send_receiver(ret),
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY),
		SPCI_INVALID_PARAMETERS);

	/* Give the memory back and notify the sender. */
	msg_size = spci_memory_relinquish_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		memory_region->constituent_count, 0);
	EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
				msg_size, SPCI_MSG_SEND_LEGACY_MEMORY)
			  .func,
		  SPCI_SUCCESS_32);

	/* Ensure we cannot lend from the primary to another secondary. */
	msg_size = spci_memory_lend_init(
		send_buf, SERVICE_VM1, constituents,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY),
			  SPCI_INVALID_PARAMETERS);

	/* Ensure we cannot share from the primary to another secondary. */
	msg_size = spci_memory_share_init(
		send_buf, SERVICE_VM1, constituents,
		memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY),
			  SPCI_INVALID_PARAMETERS);

	spci_yield();
}

/**
 * SPCI: Attempt to execute an instruction from the lent memory.
 */
TEST_SERVICE(spci_memory_lend_relinquish_X)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint64_t *ptr;
		uint32_t msg_size;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);
		spci_rx_release();

		ptr = (uint64_t *)constituents[0].address;
		/*
		 * Verify that the instruction in memory is the encoded RET
		 * instruction.
		 */
		EXPECT_EQ(*ptr, 0xD65F03C0);
		/* Try to execute instruction from the shared memory region. */
		__asm__ volatile("blr %0" ::"r"(ptr));

		/* Release the memory again. */
		msg_size = spci_memory_relinquish_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0);
		EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret),
					HF_PRIMARY_VM_ID, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY)
				  .func,
			  SPCI_SUCCESS_32);
	}
}

/**
 * SPCI: Attempt to read and write to a shared page.
 */
TEST_SERVICE(spci_memory_lend_relinquish_RW)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			spci_get_memory_region(recv_buf);
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY);
		spci_rx_release();

		ptr = (uint8_t *)constituents[0].address;

		/* Check that we have read access. */
		for (int i = 0; i < PAGE_SIZE; ++i) {
			EXPECT_EQ(ptr[i], 'b');
		}

		/* Return control to primary, to verify shared access. */
		spci_yield();

		/* Attempt to modify the memory. */
		for (int i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		msg_size = spci_memory_relinquish_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0);
		EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret),
					HF_PRIMARY_VM_ID, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY)
				  .func,
			  SPCI_SUCCESS_32);
	}
}

/**
 * SPCI: Attempt to modify below the lower bound for the lent memory.
 */
TEST_SERVICE(spci_lend_check_lower_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;

	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	ptr = (uint8_t *)constituents[0].address;

	/* Check that one cannot access before donated region. */
	ptr[-1]++;
}

/**
 * SPCI: Attempt to modify above the upper bound for the lent memory.
 */
TEST_SERVICE(spci_lend_check_upper_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;

	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	ptr = (uint8_t *)constituents[0].address;

	/* Check that one cannot access after donated region. */
	ptr[PAGE_SIZE]++;
}

TEST_SERVICE(spci_memory_lend_twice)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint32_t msg_size;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		spci_get_memory_region(recv_buf);
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret), SPCI_MSG_SEND_LEGACY_MEMORY);
	spci_rx_release();

	ptr = (uint8_t *)constituents[0].address;

	/* Check that we have read access. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		EXPECT_EQ(ptr[i], 'b');
	}

	/* Return control to primary. */
	spci_yield();

	/* Attempt to modify the memory. */
	for (int i = 0; i < PAGE_SIZE; ++i) {
		ptr[i]++;
	}

	for (int i = 1; i < PAGE_SIZE * 2; i++) {
		constituents[0].address = (uint64_t)ptr + i;

		/* Fail to lend or share the memory back to the primary. */
		msg_size = spci_memory_lend_init(
			send_buf, SERVICE_VM1, constituents,
			memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
			SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		EXPECT_SPCI_ERROR(
			spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size,
				      SPCI_MSG_SEND_LEGACY_MEMORY),
			SPCI_INVALID_PARAMETERS);
		msg_size = spci_memory_share_init(
			send_buf, SERVICE_VM1, constituents,
			memory_region->constituent_count, 0, SPCI_MEMORY_RW_X,
			SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		EXPECT_SPCI_ERROR(
			spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM1, msg_size,
				      SPCI_MSG_SEND_LEGACY_MEMORY),
			SPCI_INVALID_PARAMETERS);
	}

	msg_size = spci_memory_relinquish_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		memory_region->constituent_count, 0);
	EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
				msg_size, SPCI_MSG_SEND_LEGACY_MEMORY)
			  .func,
		  SPCI_SUCCESS_32);
}
