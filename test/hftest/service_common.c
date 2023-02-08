/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/fdt_handler.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/hftest_impl.h"
#include "test/vmapi/ffa.h"

HFTEST_ENABLE();

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

static struct hftest_context global_context;

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

noreturn void abort(void)
{
	HFTEST_LOG("Service contained failures.");
	/* Cause a fault, as a secondary/SP can't power down the machine. */
	*((volatile uint8_t *)1) = 1;

	/* This should never be reached, but to make the compiler happy... */
	for (;;) {
	}
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

void hftest_context_init(struct hftest_context *ctx, void *send, void *recv)
{
	memset_s(ctx, sizeof(*ctx), 0, sizeof(*ctx));
	ctx->abort = abort;
	ctx->send = send;
	ctx->recv = recv;
}

noreturn void hftest_service_main(const void *fdt_ptr)
{
	struct memiter args;
	hftest_test_fn service;
	struct hftest_context *ctx;
	struct ffa_value ret;
	struct fdt fdt;
	ffa_vm_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_notifications_bitmap_t bitmap;
	struct ffa_partition_msg *message = (struct ffa_partition_msg *)mb.recv;

	/* Receive the name of the service to run. */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/*
	 * Expect to wake up with indirect message related to the next service
	 * to be executed.
	 */
	ret = ffa_notification_get(own_id, 0,
				   FFA_NOTIFICATION_FLAG_BITMAP_SPM |
					   FFA_NOTIFICATION_FLAG_BITMAP_HYP);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	bitmap = ffa_notification_get_from_framework(ret);
	ASSERT_TRUE(is_ffa_spm_buffer_full_notification(bitmap) ||
		    is_ffa_hyp_buffer_full_notification(bitmap));
	ASSERT_EQ(own_id, ffa_rxtx_header_receiver(&message->header));
	memiter_init(&args, message->payload, message->header.size);

	/* Find service handler. */
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
	hftest_context_init(ctx, mb.send, mb.recv);

	/*
	 * The memory size argument is to be used only by VMs. It is part of
	 * the dt provided by the Hypervisor. SPs expect to receive their
	 * FF-A manifest which doesn't have a memory size field.
	 */
	if (!IS_SP_ID(own_id) &&
	    !fdt_get_memory_size(&fdt, &ctx->memory_size)) {
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

ffa_vm_id_t hftest_get_dir_req_source_id(void)
{
	struct hftest_context *ctx = hftest_get_context();
	return ctx->dir_req_source_id;
}

void hftest_set_dir_req_source_id(ffa_vm_id_t id)
{
	struct hftest_context *ctx = hftest_get_context();
	ctx->dir_req_source_id = id;
}
