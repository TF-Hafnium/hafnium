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

#define FORWARD_TIMER_CMD 1

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

/**
 * This test requests SP to program the timer with a long deadline and then
 * requests again to program with a short deadline. SPMC shall honor the most
 * recent configuration of the arch timer by the SP.
 */
TEST(arch_timer, reprogram_deadline)
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

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 100,
						   SP_SHORT_SLEEP, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 5,
						   SP_SHORT_SLEEP, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Timer deadline would have expired during this time. SP will handle
	 * the virtual timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SHORT_SLEEP);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}

static void enable_arch_timer_virtual_interrupt_all_sp(ffa_id_t own_id,
						       ffa_id_t receiver1_id,
						       ffa_id_t receiver2_id,
						       ffa_id_t receiver3_id)
{
	struct ffa_value res;

	res = sp_virtual_interrupt_cmd_send(own_id, receiver1_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_virtual_interrupt_cmd_send(own_id, receiver2_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_virtual_interrupt_cmd_send(own_id, receiver3_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void check_arch_timer_virtual_interrupt_serviced_all_sp(
	ffa_id_t own_id, ffa_id_t receiver1_id, ffa_id_t receiver2_id,
	ffa_id_t receiver3_id)
{
	struct ffa_value res;

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver1_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);

	res = sp_get_last_interrupt_cmd_send(own_id, receiver2_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);

	res = sp_get_last_interrupt_cmd_send(own_id, receiver3_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}

/**
 * This test initiates a request to form a long normal world call chain with all
 * three SPs. Each SP programs a short deadline followed by a short sleep. The
 * choice of deadline and sleep delay are such that the first SP's deadline
 * expires while execution is in SWd and the third SP's deadline expires while
 * execution is in NWd.
 */
TEST(arch_timer, cascaded_timer_deadlines_long_callchain)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	const ffa_id_t receiver1_id = service1_info->vm_id;
	const ffa_id_t receiver2_id = service2_info->vm_id;
	const ffa_id_t receiver3_id = service3_info->vm_id;

	enable_arch_timer_virtual_interrupt_all_sp(own_id, receiver1_id,
						   receiver2_id, receiver3_id);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver1_id, 10, 5,
						   FORWARD_TIMER_CMD);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Any pending timer's deadline should expire during this time, SP will
	 * handle the virtual timer interrupt.
	 */
	waitms(10);

	check_arch_timer_virtual_interrupt_serviced_all_sp(
		own_id, receiver1_id, receiver2_id, receiver3_id);
}

/**
 * This test is very similar to above test except that the NWd test driver
 * requests each SP to program a deadline followed by a short sleep.
 */
TEST(arch_timer, multiple_sp_deadline)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	const ffa_id_t receiver1_id = service1_info->vm_id;
	const ffa_id_t receiver2_id = service2_info->vm_id;
	const ffa_id_t receiver3_id = service3_info->vm_id;

	enable_arch_timer_virtual_interrupt_all_sp(own_id, receiver1_id,
						   receiver2_id, receiver3_id);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver1_id, 10, 5,
						   0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver2_id, 10, 5,
						   0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver3_id, 10, 5,
						   0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Any pending timer's deadline should expire during this time, SP will
	 * handle the virtual timer interrupt.
	 */
	waitms(10);

	check_arch_timer_virtual_interrupt_serviced_all_sp(
		own_id, receiver1_id, receiver2_id, receiver3_id);
}
