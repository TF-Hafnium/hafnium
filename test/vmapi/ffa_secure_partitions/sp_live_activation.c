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

/**
 * This helper drives live activation test and verifies that the SPMC preserves
 * framework state across activations of a secure partition.
 */
void base_live_activate_sp(ffa_id_t receiver_id, uint32_t component_id)
{
	ffa_id_t own_id = hf_vm_get_id();

	EXPECT_EQ(ffa_version(FFA_VERSION_1_3), FFA_VERSION_COMPILED);
	check_echo(own_id, receiver_id);

	start_live_activation_sequence(component_id);
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
