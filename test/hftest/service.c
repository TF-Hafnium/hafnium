/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/interrupts.h"

#include "hf/fdt_handler.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "msr.h"
#include "test/hftest.h"

alignas(4096) uint8_t kstack[4096];

HFTEST_ENABLE();

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

static alignas(HF_MAILBOX_SIZE) uint8_t send[HF_MAILBOX_SIZE];
static alignas(HF_MAILBOX_SIZE) uint8_t recv[HF_MAILBOX_SIZE];

static hf_ipaddr_t send_addr = (hf_ipaddr_t)send;
static hf_ipaddr_t recv_addr = (hf_ipaddr_t)recv;

static struct hftest_context global_context;

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

/** Find the service with the name passed in the arguments. */
static hftest_test_fn find_service(struct memiter *args)
{
	struct memiter service_name;
	struct hftest_test *test;

	if (!memiter_parse_str(args, &service_name)) {
		return NULL;
	}

	for (test = hftest_begin; test < hftest_end; ++test) {
		if (test->kind == HFTEST_KIND_SERVICE &&
		    memiter_iseq(&service_name, test->name)) {
			return test->fn;
		}
	}

	return NULL;
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

noreturn void kmain(const void *fdt_ptr)
{
	struct memiter args;
	hftest_test_fn service;
	struct hftest_context *ctx;
	struct ffa_value ret;
	struct fdt fdt;

	/*
	 * Initialize the stage-1 MMU and identity-map the entire address space.
	 */
	if (!hftest_mm_init()) {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT "Memory initialization failed");
		abort();
	}

	/* Setup basic exception handling. */
	exception_setup(NULL, NULL);

	/* Prepare the context. */

	/* Set up the mailbox. */
	ffa_rxtx_map(send_addr, recv_addr);

	/* Receive the name of the service to run. */
	ret = ffa_msg_wait();
	ASSERT_EQ(ret.func, FFA_MSG_SEND_32);
	memiter_init(&args, recv, ffa_msg_send_size(ret));
	service = find_service(&args);
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	/* Check the service was found. */
	if (service == NULL) {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "Unable to find requested service");
		abort();
	}

	if (!fdt_struct_from_ptr(fdt_ptr, &fdt)) {
		HFTEST_LOG(HFTEST_LOG_INDENT "Unable to access the FDT");
		abort();
	}

	/* Clean the context. */
	ctx = hftest_get_context();
	memset_s(ctx, sizeof(*ctx), 0, sizeof(*ctx));
	ctx->abort = abort;
	ctx->send = send;
	ctx->recv = recv;
	if (!fdt_get_memory_size(&fdt, &ctx->memory_size)) {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "No entry in the FDT on memory size details");
		abort();
	}

	/* Pause so the next time cycles are given the service will be run. */
	ffa_yield();

	/* Let the service run. */
	service();

	/* Cleanly handle it if the service returns. */
	if (ctx->failures) {
		abort();
	}

	for (;;) {
		/* Hang if the service returns. */
	}
}
