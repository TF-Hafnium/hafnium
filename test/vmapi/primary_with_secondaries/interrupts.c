/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stddef.h>
#include <stdint.h>

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(interrupts)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

static void receive_and_check_expected(char* response, size_t response_size,
				       void* recv,
				       const char* expected_response,
				       size_t expected_response_size,
				       ffa_id_t expected_sender)
{
	ffa_id_t sender;

	receive_indirect_message(response, response_size, recv, &sender);
	EXPECT_EQ(sender, expected_sender);
	EXPECT_EQ(memcmp(response, expected_response, expected_response_size),
		  0);
}

/**
 * Send a message to the interruptible VM, which will interrupt itself to send a
 * response back.
 */
TEST(interrupts, interrupt_self)
{
	const char message[] = "Ping";
	const char expected_response[] = "Got IRQ 05.";
	char response[sizeof(expected_response)];
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(SERVICE_VM1, "interruptible", mb.send);

	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Set the message, echo it and wait for a response. */
	ret = send_indirect_message(own_id, SERVICE_VM1, mb.send, message,
				    sizeof(message), 0);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);
}

/**
 * Inject an interrupt to the interrupt VM, which will send a message back.
 * Repeat this twice to make sure it doesn't get into a bad state after the
 * first one.
 */
TEST(interrupts, inject_interrupt_twice)
{
	const char expected_response[] = "Got IRQ 07.";
	char response[sizeof(expected_response)];
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "interruptible", mb.send);

	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Inject the interrupt and wait for a message. */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);

	/* Inject the interrupt again, and wait for the same message. */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);
}

/**
 * Inject two different interrupts to the interrupt VM, which will send a
 * message back each time.
 */
TEST(interrupts, inject_two_interrupts)
{
	const char expected_response[] = "Got IRQ 07.";
	const char expected_response_2[] = "Got IRQ 08.";
	struct mailbox_buffers mb = set_up_mailbox();
	char response[sizeof(expected_response)];
	struct ffa_value ret;

	SERVICE_SELECT(SERVICE_VM1, "interruptible", mb.send);

	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Inject the interrupt and wait for a message. */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);

	/* Inject a different interrupt and wait for a different message. */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_B);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response_2,
				   sizeof(expected_response_2), SERVICE_VM1);
}

/**
 * Inject an interrupt then send a message to the interrupt VM, which will send
 * a message back each time. This is to test that interrupt injection doesn't
 * interfere with message reception.
 */
TEST(interrupts, inject_interrupt_message)
{
	const char expected_response[] = "Got IRQ 07.";
	const char message[] = "Ping";
	const char expected_response_2[] = "Got IRQ 05.";
	char response[sizeof(expected_response)];
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(SERVICE_VM1, "interruptible", mb.send);

	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Inject the interrupt and wait for a message. */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);

	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/* Now send a message to the secondary. */
	send_indirect_message(own_id, SERVICE_VM1, mb.send, message,
			      sizeof(message), 0);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);
	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response_2,
				   sizeof(expected_response_2), SERVICE_VM1);
}

/**
 * Inject an interrupt which the target VM has not enabled, and then send a
 * message telling it to enable that interrupt ID. It should then (and only
 * then) send a message back.
 */
TEST(interrupts, inject_interrupt_disabled)
{
	const char expected_response[] = "Got IRQ 09.";
	const char message[] = "Enable interrupt C";
	char response[sizeof(expected_response)];
	struct ffa_value ret;
	struct mailbox_buffers mb = set_up_mailbox();
	const ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(SERVICE_VM1, "interruptible", mb.send);

	/* Inject the interrupt and expect not to get a message. */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_C);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_MSG_WAIT_32);

	/*
	 * Now send a message to the secondary to enable the interrupt ID, and
	 * expect the response from the interrupt we sent before.
	 */
	send_indirect_message(own_id, SERVICE_VM1, mb.send, message,
			      sizeof(message), 0);
	ret = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);
}

/**
 * If a secondary VM has an enabled and pending interrupt, even if interrupts
 * are disabled globally via PSTATE, then hf_mailbox_receive should not block
 * even if `block` is true.
 */
TEST(interrupts, pending_interrupt_no_blocking_receive)
{
	const char expected_response[] = "Done waiting";
	char response[sizeof(expected_response)];
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "receive_block", mb.send);

	/*
	 * Inject the interrupt and run the VM. It should disable interrupts
	 * globally, enable the specific interrupt, and then send us a message
	 * back after failing to receive a message a few times.
	 */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);

	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);
}

/**
 * If a secondary VM has an enabled and pending interrupt, even if interrupts
 * are disabled globally via PSTATE, then WFI should be treated as a no-op and
 * not return to the primary.
 */
TEST(interrupts, pending_interrupt_wfi_not_trapped)
{
	const char expected_response[] = "Done waiting";
	char response[sizeof(expected_response)];
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "wfi", mb.send);

	/*
	 * Inject the interrupt and run the VM. It should disable interrupts
	 * globally, enable the specific interrupt, and then send us a message
	 * back after running WFI a few times.
	 */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
	receive_and_check_expected(response, sizeof(response), mb.recv,
				   expected_response, sizeof(expected_response),
				   SERVICE_VM1);
}

/*
 * Deliver an interrupt and a message to the same vCPU and check that both are
 * delivered the next time the vCPU is run.
 */
TEST(interrupts, deliver_interrupt_and_message)
{
	const char message[] = "I\'ll see you again.";
	char response[sizeof(message)];
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_id_t own_id = hf_vm_get_id();

	SERVICE_SELECT(SERVICE_VM1, "interruptible_echo", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);

	send_indirect_message(own_id, SERVICE_VM1, mb.send, message,
			      sizeof(message), 0);
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);
	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_MSG_WAIT_32);

	receive_and_check_expected(response, sizeof(response), mb.recv, message,
				   sizeof(message), SERVICE_VM1);
}

/**
 * The secondary vCPU is waiting for a direct msg request, but the primary
 * instead injects an interrupt into it and calls FFA_RUN. The secondary
 * should get FFA_INTERRUPT_32 returned, as well as the interrupt itself.
 */
TEST(interrupts_direct_msg, direct_msg_request_interrupted)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1, "interruptible_echo_direct_msg", mb.send);

	/* Let the secondary get started and wait for a message. */
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	/* Send an initial direct message request */
	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 2);

	/* Inject an interrupt to the secondary VM */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);

	/* Let the secondary VM run */
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 3, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 4);
}

/**
 * The secondary vCPU is waiting for a direct request. The primary injects
 * an interrupt into it and then calls FFA_MSG_SEND_DIRECT_REQ. The secondary
 * shall get both the direct request and the interrupt.
 */
TEST(interrupts_direct_msg, direct_msg_request_with_interrupt)
{
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_value res;

	SERVICE_SELECT(SERVICE_VM1,
		       "interruptible_echo_direct_msg_with_interrupt", mb.send);

	/* Let the secondary get started and wait for a message. */
	res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(res.func, FFA_MSG_WAIT_32);

	/* Inject an interrupt to the secondary VM */
	hf_interrupt_inject(SERVICE_VM1, 0, EXTERNAL_INTERRUPT_ID_A);

	/*
	 * Send a direct message request. Expect the secondary VM to receive
	 * the message and the interrupt together. The secondary VM then
	 * replies with a direct message response.
	 */
	res = ffa_msg_send_direct_req(HF_PRIMARY_VM_ID, SERVICE_VM1, 1, 0, 0, 0,
				      0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, 2);
}
