/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "ffa_secure_partitions.h"
#include "partition_services.h"
#include "sp_helpers.h"

#define SP_SLEEP_TIME 400U

static void configure_trusted_wdog_interrupt(ffa_vm_id_t source,
					     ffa_vm_id_t dest, bool enable)
{
	struct ffa_value res;

	res = sp_virtual_interrupt_cmd_send(source, dest, IRQ_TWDOG_INTID,
					    enable, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void enable_trusted_wdog_interrupt(ffa_vm_id_t source, ffa_vm_id_t dest)
{
	configure_trusted_wdog_interrupt(source, dest, true);
}

static void disable_trusted_wdog_interrupt(ffa_vm_id_t source, ffa_vm_id_t dest)
{
	configure_trusted_wdog_interrupt(source, dest, false);
}

static void enable_trigger_trusted_wdog_timer(ffa_vm_id_t own_id,
					      ffa_vm_id_t receiver_id,
					      uint32_t timer_ms)
{
	struct ffa_value res;

	/* Enable trusted watchdog interrupt as vIRQ in the secure side. */
	enable_trusted_wdog_interrupt(own_id, receiver_id);

	res = sp_twdog_map_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Send a message to the SP through direct messaging requesting it to
	 * start the trusted watchdog timer.
	 */
	res = sp_twdog_cmd_send(own_id, receiver_id, timer_ms);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void check_and_disable_trusted_wdog_timer(ffa_vm_id_t own_id,
						 ffa_vm_id_t receiver_id)
{
	struct ffa_value res;

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure Trusted Watchdog timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), IRQ_TWDOG_INTID);

	/* Disable Trusted Watchdog interrupt. */
	disable_trusted_wdog_interrupt(own_id, receiver_id);
}

/*
 * Test secure interrupt handling while the Secure Partition is in RUNNING
 * state.
 */
TEST(secure_interrupts, sp_running)
{
	struct ffa_value res;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct ffa_partition_info *service2_info = service2();
	const ffa_vm_id_t receiver_id = service2_info->vm_id;

	enable_trigger_trusted_wdog_timer(own_id, receiver_id, 400);

	/* Send request to the SP to sleep. */
	res = sp_sleep_cmd_send(own_id, receiver_id, SP_SLEEP_TIME);

	/*
	 * Secure interrupt should trigger during this time, SP will handle the
	 * trusted watchdog timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

	check_and_disable_trusted_wdog_timer(own_id, receiver_id);
}
