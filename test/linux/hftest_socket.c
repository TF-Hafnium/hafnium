/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/transport.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

alignas(4096) uint8_t kstack[4096];

static alignas(HF_MAILBOX_SIZE) uint8_t send[HF_MAILBOX_SIZE];
static alignas(HF_MAILBOX_SIZE) uint8_t recv[HF_MAILBOX_SIZE];

static hf_ipaddr_t send_addr = (hf_ipaddr_t)send;
static hf_ipaddr_t recv_addr = (hf_ipaddr_t)recv;

static struct hftest_context global_context;

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

noreturn void abort(void)
{
	HFTEST_LOG("Service contained failures.");
	/* Cause a fault, as a secondary can't power down the machine. */
	*((volatile uint8_t *)1) = 1;

	/* This should never be reached, but to make the compiler happy... */
	for (;;) {
	}
}

static void swap(uint64_t *a, uint64_t *b)
{
	uint64_t t = *a;
	*a = *b;
	*b = t;
}

noreturn void kmain(size_t memory_size)
{
	struct hftest_context *ctx;

	/* Prepare the context. */

	/* Set up the mailbox. */
	ffa_rxtx_map(send_addr, recv_addr);

	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);

	/* Clean the context. */
	ctx = hftest_get_context();
	memset_s(ctx, sizeof(*ctx), 0, sizeof(*ctx));
	ctx->abort = abort;
	ctx->send = send;
	ctx->recv = recv;
	ctx->memory_size = memory_size;

	for (;;) {
		struct ffa_value ret;

		/* Receive the packet. */
		ret = ffa_msg_wait();
		EXPECT_EQ(ret.func, FFA_MSG_SEND_32);
		EXPECT_LE(ffa_msg_send_size(ret), FFA_MSG_PAYLOAD_MAX);

		/* Echo the message back to the sender. */
		memcpy_s(send, FFA_MSG_PAYLOAD_MAX, recv,
			 ffa_msg_send_size(ret));

		/* Swap the socket's source and destination ports */
		struct hf_msg_hdr *hdr = (struct hf_msg_hdr *)send;
		swap(&(hdr->src_port), &(hdr->dst_port));

		/* Swap the destination and source ids. */
		ffa_id_t dst_id = ffa_sender(ret);
		ffa_id_t src_id = ffa_receiver(ret);

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
		EXPECT_EQ(
			ffa_msg_send(src_id, dst_id, ffa_msg_send_size(ret), 0)
				.func,
			FFA_SUCCESS_32);
	}
}
