/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/lfa_helpers.h"

#include "hf/ffa.h"
#include "hf/ffa_v1_0.h"

#include "ap_refclk_generic_timer.h"
#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "sp_helpers.h"

/*
 * SP1 GUID lower Bytes (0 through 7) and higher Bytes (8 through 15)
 */
#define GUID_LOWER_SP1 (0x174d471d962a7bf0)
#define GUID_HIGHER_SP1 (0x5c3e254ea686c89e)

/*
 * SP2 GUID lower Bytes (0 through 7) and higher Bytes (8 through 15)
 */
#define GUID_LOWER_SP2 (0xf8a9417e2721ffc3)
#define GUID_HIGHER_SP2 (0x7434a3afa124af05)

/* Forward declaration for share helper */
static void share_page_with_target_sp(ffa_id_t receiver_id);

alignas(PAGE_SIZE) static uint8_t
	shared_pages[FRAGMENTED_SHARE_PAGE_COUNT * PAGE_SIZE];

bool is_activation_pending(uint32_t flags)
{
	return (flags & LFA_FLAGS_ACTIVATION_PENDING) != 0U;
}

bool is_activation_capable(uint32_t flags)
{
	return (flags & LFA_FLAGS_ACTIVATION_CAPABLE) != 0U;
}

bool is_cpu_reset_during_live_activation(uint32_t flags)
{
	return (flags & LFA_FLAGS_MAY_RESET_CPU) != 0U;
}

bool is_cpu_rendezvous_required(uint32_t flags)
{
	return (flags & LFA_FLAGS_CPU_RENDEZVOUS) == 0U;
}

/*
 * Helper: verify LFA framework version, component count, and inventory error.
 */
static uint32_t check_lfa_framework(void)
{
	struct ffa_value res;
	uint64_t lfa_version = lfa_get_version();
	EXPECT_EQ(lfa_version, (LFA_MAJOR_VERSION << 16) | LFA_MINOR_VERSION);

	uint32_t fw_component_count = lfa_get_info();
	EXPECT_GE(fw_component_count, 0);

	res = lfa_get_inventory(fw_component_count);
	EXPECT_EQ((uint32_t)res.func, LFA_INVALID_PARAMETERS);

	return fw_component_count;
}

/*
 *
 */
static bool find_component_id_by_guid(uint64_t guid_lower, uint64_t guid_higher,
				      uint32_t *component_id,
				      uint32_t fw_component_count)
{
	struct ffa_value res;

	if (component_id == NULL || guid_lower == 0U || guid_higher == 0U) {
		return false;
	}

	for (uint32_t i = 0U; i < fw_component_count; i++) {
		res = lfa_get_inventory(i);
		EXPECT_EQ((uint32_t)res.func, LFA_SUCCESS);

		if (res.arg1 == guid_lower && res.arg2 == guid_higher) {
			*component_id = i;
			return true;
		}
	}

	return false;
}

static void share_page_with_target_sp(ffa_id_t receiver_id)
{
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const ffa_id_t sender_id = hf_vm_get_id();

	struct ffa_memory_region_constituent constituents[] = {
		{.address = (uint64_t)shared_pages, .page_count = 1},
	};

	struct ffa_memory_access receiver_v1_2;
	struct ffa_memory_access_impdef impdef =
		ffa_memory_access_impdef_init(receiver_id, receiver_id + 1);

	uint32_t total_length;
	uint32_t fragment_length;
	uint32_t remaining_constituent_count;
	ffa_memory_handle_t handle;

	/* Initialise the memory before giving it. */
	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		shared_pages[i] = i;
	}

	ffa_memory_access_init(&receiver_v1_2, receiver_id, FFA_DATA_ACCESS_RW,
			       FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED, 0,
			       &impdef);

	remaining_constituent_count = ffa_memory_region_init(
		mb.send, HF_MAILBOX_SIZE, sender_id, &receiver_v1_2, 1,
		sizeof(struct ffa_memory_access), constituents,
		ARRAY_SIZE(constituents), 0, 0, FFA_MEMORY_NORMAL_MEM,
		FFA_MEMORY_CACHE_WRITE_BACK, FFA_MEMORY_INNER_SHAREABLE,
		&fragment_length, &total_length);
	EXPECT_EQ(remaining_constituent_count, 0);
	EXPECT_EQ(fragment_length, total_length);

	ret = ffa_mem_share(total_length, fragment_length);
	handle = ffa_mem_success_handle(ret);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_NE(handle, FFA_MEMORY_HANDLE_INVALID);

	(void)sp_ffa_mem_retrieve_cmd_send(sender_id, receiver_id, handle,
					   FFA_VERSION_1_3);
}

/*
 * Increment shared buffer and validate contents are equal to expected_val.
 */
static void increment_and_validate_shared_buffer(ffa_id_t own_id,
						 ffa_id_t receiver_id,
						 uint8_t expected_val)
{
	struct ffa_value res;
	res = sp_increment_shared_buffer_cmd_send(own_id, receiver_id);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	for (uint32_t i = 0; i < PAGE_SIZE; i++) {
		ASSERT_EQ(shared_pages[i], (uint8_t)(i + expected_val));
	}
}

/*
 * Helper function to bind notifications.
 */
static void setup_notifications(ffa_id_t own_id, ffa_id_t receiver_id,
				uint32_t flags,
				ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;
	res = sp_notif_bind_cmd_send(own_id, receiver_id, own_id,
				     flags & FFA_NOTIFICATION_FLAG_PER_VCPU,
				     bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

/*
 * Helper function to set notifications and get notification info.
 */
static void initiate_notifications(ffa_id_t own_id, ffa_id_t receiver_id,
				   uint32_t flags,
				   ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;

	res = ffa_notification_set(own_id, receiver_id, flags, bitmap);
	EXPECT_EQ(res.func, FFA_SUCCESS_32);

	res = ffa_notification_info_get();
	EXPECT_EQ(res.func, FFA_SUCCESS_64);
}

/*
 * Helper function to retrieve and unbind notifications, validating the bitmap.
 */
static void get_notifications(ffa_id_t own_id, ffa_id_t receiver_id,
			      ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;
	res = sp_notif_get_cmd_send(own_id, receiver_id, 0,
				    FFA_NOTIFICATION_FLAG_BITMAP_VM);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
	EXPECT_EQ(sp_notif_get_from_sp(res), 0);
	EXPECT_EQ(sp_notif_get_from_vm(res), bitmap);
}

static void unbind_notifications(ffa_id_t own_id, ffa_id_t receiver_id,
				 ffa_notifications_bitmap_t bitmap)
{
	struct ffa_value res;

	res = sp_notif_unbind_cmd_send(own_id, receiver_id, own_id, bitmap);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void set_partition_stop_resp_status(ffa_id_t own_id,
					   ffa_id_t receiver_id,
					   uint32_t status)
{
	struct ffa_value res;

	res = sp_set_partition_stop_resp_status_cmd_send(own_id, receiver_id,
							 status);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void start_live_activation_sequence(uint32_t component_id)
{
	struct ffa_value res;
	uint32_t lfa_flags;
	enum lfa_return_code lfa_ret;

	res = lfa_get_inventory(component_id);

	EXPECT_EQ((uint32_t)res.func, LFA_SUCCESS);
	lfa_flags = (uint32_t)res.arg3;

	dlog("GUID: %lx - %lx", res.arg1, res.arg2);
	dlog_verbose("Flags: %lx", res.arg3);

	EXPECT_TRUE(is_activation_pending(lfa_flags));

	EXPECT_TRUE(is_activation_capable(lfa_flags));

	EXPECT_FALSE(is_cpu_reset_during_live_activation(lfa_flags));

	EXPECT_FALSE(is_cpu_rendezvous_required(lfa_flags));

	/* LFA prime should succeed. Not needed to call again. */
	res = lfa_prime(component_id);

	EXPECT_EQ((uint32_t)res.func, LFA_SUCCESS);
	EXPECT_EQ(res.arg1, 0U);

	/* Live Activate SP. */
	lfa_ret = lfa_activate(component_id, 1, 0, 0);

	EXPECT_EQ(lfa_ret, LFA_SUCCESS);
}

static void start_live_activation_sequence_expect_failure(uint32_t component_id)
{
	struct ffa_value res;
	uint32_t lfa_flags;
	enum lfa_return_code lfa_ret;

	res = lfa_get_inventory(component_id);

	EXPECT_EQ((uint32_t)res.func, LFA_SUCCESS);
	lfa_flags = (uint32_t)res.arg3;

	dlog("GUID: %lx - %lx", res.arg1, res.arg2);
	dlog_verbose("Flags: %lx", res.arg3);

	EXPECT_TRUE(is_activation_pending(lfa_flags));

	EXPECT_TRUE(is_activation_capable(lfa_flags));

	EXPECT_FALSE(is_cpu_reset_during_live_activation(lfa_flags));

	EXPECT_FALSE(is_cpu_rendezvous_required(lfa_flags));

	/* LFA prime should succeed. Not needed to call again. */
	res = lfa_prime(component_id);

	EXPECT_EQ((uint32_t)res.func, LFA_SUCCESS);
	EXPECT_EQ(res.arg1, 0U);

	/* Live Activate SP. */
	lfa_ret = lfa_activate(component_id, 1, 0, 0);

	EXPECT_NE(lfa_ret, LFA_SUCCESS);
}

/**
 * This helper drives live activation test and verifies that the SPMC preserves
 * framework state across activations of a secure partition.
 * In summary, it:
 *   - Shares a memory page with the partition.
 *   - Performs an initial message exchange and notification setup.
 *   - Triggers live activation for the specified component twice.
 *   - After each activation, validates that shared memory contents and
 *     notifications remain intact.
 */
void base_live_activate_sp(ffa_id_t receiver_id, uint32_t component_id)
{
	uint32_t flags;
	ffa_notifications_bitmap_t bitmap;
	ffa_id_t own_id = hf_vm_get_id();

	EXPECT_EQ(ffa_version(FFA_VERSION_1_3), FFA_VERSION_COMPILED);
	check_echo(own_id, receiver_id);

	/* Share a page with target SP. */
	share_page_with_target_sp(receiver_id);
	increment_and_validate_shared_buffer(own_id, receiver_id, 1);

	flags = FFA_NOTIFICATIONS_FLAG_DELAY_SRI;
	bitmap = FFA_NOTIFICATION_MASK(35);
	setup_notifications(own_id, receiver_id, flags, bitmap);

	/* First live activation */
	initiate_notifications(own_id, receiver_id, flags, bitmap);
	start_live_activation_sequence(component_id);
	increment_and_validate_shared_buffer(own_id, receiver_id, 2);
	get_notifications(own_id, receiver_id, bitmap);

	/* Second live activation */
	initiate_notifications(own_id, receiver_id, flags, bitmap);
	start_live_activation_sequence(component_id);
	increment_and_validate_shared_buffer(own_id, receiver_id, 3);
	get_notifications(own_id, receiver_id, bitmap);

	/* Clean up. */
	unbind_notifications(own_id, receiver_id, bitmap);
}

/**
 * Test to validate support for live activating an S-EL1 partition.
 */
TEST(live_activation, live_activate_sel1_sp)
{
	uint32_t component_id = 0;
	uint32_t fw_component_count = 0;

	fw_component_count = check_lfa_framework();
	EXPECT_TRUE(find_component_id_by_guid(GUID_LOWER_SP1, GUID_HIGHER_SP1,
					      &component_id,
					      fw_component_count));

	base_live_activate_sp(SP_ID(1), component_id);
}

/**
 * Test to validate support for live activating an S-EL0 partition.
 */
TEST(live_activation, live_activate_sel0_sp)
{
	uint32_t component_id = 0;
	uint32_t fw_component_count = 0;

	fw_component_count = check_lfa_framework();
	EXPECT_TRUE(find_component_id_by_guid(GUID_LOWER_SP2, GUID_HIGHER_SP2,
					      &component_id,
					      fw_component_count));

	base_live_activate_sp(SP_ID(2), component_id);
}

/**
 * Test to validate error propagation when the SP responds to the partition
 * stop framework message with a non-success status. The live activation request
 * should fail in the LFA call path.
 */
TEST(live_activation, live_activate_sp_stop_request_error)
{
	uint32_t component_id = 0;
	uint32_t fw_component_count = 0;
	ffa_id_t own_id = hf_vm_get_id();

	fw_component_count = check_lfa_framework();
	EXPECT_TRUE(find_component_id_by_guid(GUID_LOWER_SP1, GUID_HIGHER_SP1,
					      &component_id,
					      fw_component_count));

	EXPECT_EQ(ffa_version(FFA_VERSION_1_3), FFA_VERSION_COMPILED);
	check_echo(own_id, SP_ID(1));

	set_partition_stop_resp_status(own_id, SP_ID(1), FFA_ABORTED);
	start_live_activation_sequence_expect_failure(component_id);
}
