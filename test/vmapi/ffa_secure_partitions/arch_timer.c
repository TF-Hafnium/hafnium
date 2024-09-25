/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/delay.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/power_mgmt.h"
#include "hf/arch/vm/timer.h"

#include "ffa_secure_partitions.h"
#include "gicv3.h"
#include "partition_services.h"
#include "sp805.h"
#include "sp_helpers.h"

#define SP_SLEEP_TIME 100U
#define SP_SHORT_SLEEP 10U

/**
 * This test requests SP to start the timer with short deadline and wait for
 * few milliseconds for the deadline to expire. SPMC tracks the timer deadline
 * and signals the virtual timer interrupt which shall be handled by the SP.
 * Further, the test queries the SP for the last serviced virtual interrupt to
 * ensure virtual timer interrupt was handled.
 */
TEST(arch_timer, short_deadline)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	res = sp_virtual_interrupt_cmd_send(own_id, receiver_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 5,
						   SP_SLEEP_TIME, 0);
	/*
	 * Timer deadline would have expired during this time. SP will handle
	 * the virtual timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}
