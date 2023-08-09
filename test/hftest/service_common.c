/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/check.h"
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

/*
 * Parse the FF-A partition's manifest.
 * This function assumes the 'fdt' field of the passed 'ctx' has been
 * initialized.
 * TODO: Parse other fields as needed.
 */
static void hftest_parse_ffa_manifest(struct hftest_context *ctx,
				      struct fdt *fdt)
{
	struct fdt_node root;
	struct fdt_node ffa_node;
	struct string mem_region_node_name = STRING_INIT("memory-regions");
	uint64_t number;

	CHECK(ctx != NULL);
	CHECK(fdt != NULL);

	ASSERT_TRUE(fdt_find_node(fdt, "/", &root));
	EXPECT_TRUE(fdt_is_compatible(&root, "arm,ffa-manifest-1.0"));
	ASSERT_TRUE(fdt_read_number(&root, "load-address",
				    &ctx->partition_manifest.load_addr));
	EXPECT_TRUE(fdt_read_number(&root, "ffa-version", &number));

	ffa_node = root;

	/* Look for the memory region node. */
	if (fdt_find_child(&ffa_node, &mem_region_node_name) &&
	    fdt_first_child(&ffa_node)) {
		uint32_t mem_count = 0;

		do {
			struct memory_region *cur_region =
				&ctx->partition_manifest.mem_regions[mem_count];
			EXPECT_TRUE(fdt_read_number(&ffa_node, "pages-count",
						    &number));
			cur_region->page_count = (uint32_t)number;

			if (!fdt_read_number(&ffa_node, "base-address",
					     &cur_region->base_address)) {
				EXPECT_TRUE(fdt_read_number(&ffa_node,
							    "relative-address",
							    &number));
				cur_region->base_address =
					ctx->partition_manifest.load_addr +
					number;
			}

			EXPECT_TRUE(fdt_read_number(&ffa_node, "attributes",
						    &number));
			cur_region->attributes = (uint32_t)number;
			mem_count++;
		} while (fdt_next_sibling(&ffa_node));

		assert(mem_count < PARTITION_MAX_MEMORY_REGIONS);

		ctx->partition_manifest.mem_region_count = mem_count;
	}

	ctx->is_ffa_manifest_parsed = true;
}

static void run_service_set_up(struct hftest_context *ctx, struct fdt *fdt)
{
	struct fdt_node node;
	struct hftest_test *hftest_info;

	ASSERT_TRUE(fdt_find_node(fdt, "/", &node));

	if (!fdt_find_child(&node, &(STRING_INIT("hftest-service-setup")))) {
		return;
	}

	EXPECT_TRUE(fdt_is_compatible(&node, "arm,hftest"));

	for (hftest_info = hftest_begin; hftest_info < hftest_end;
	     ++hftest_info) {
		struct memiter data;
		if (hftest_info->kind != HFTEST_KIND_SERVICE_SET_UP) {
			continue;
		}
		if (fdt_read_property(&node, hftest_info->name, &data)) {
			HFTEST_LOG("Running service_setup: %s\n",
				   hftest_info->name);
			hftest_info->fn();
			if (ctx->failures) {
				HFTEST_LOG_FAILURE();
				HFTEST_LOG(HFTEST_LOG_INDENT
					   "%s service_setup failed\n",
					   hftest_info->name);
				abort();
			}
		} else {
			HFTEST_LOG("Skipping service_setup: %s\n",
				   hftest_info->name);
		}
	}
}

noreturn void hftest_service_main(const void *fdt_ptr)
{
	struct memiter args;
	hftest_test_fn service;
	struct hftest_context *ctx;
	struct ffa_value ret;
	struct fdt fdt;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	ffa_notifications_bitmap_t bitmap;
	struct ffa_partition_msg *message = (struct ffa_partition_msg *)mb.recv;

	/* Clean the context. */
	ctx = hftest_get_context();
	hftest_context_init(ctx, mb.send, mb.recv);

	if (!fdt_struct_from_ptr(fdt_ptr, &fdt)) {
		HFTEST_LOG(HFTEST_LOG_INDENT "Unable to access the FDT");
		abort();
	}

	/*
	 * The memory size argument is to be used only by VMs. It is part of
	 * the dt provided by the Hypervisor. SPs expect to receive their
	 * FF-A manifest which doesn't have a memory size field.
	 */
	if (ffa_is_vm_id(own_id) &&
	    !fdt_get_memory_size(&fdt, &ctx->memory_size)) {
		HFTEST_LOG_FAILURE();
		HFTEST_LOG(HFTEST_LOG_INDENT
			   "No entry in the FDT on memory size details");
		abort();
	} else if (!ffa_is_vm_id(own_id)) {
		/*
		 * It is secure partition. We are currently using the partition
		 * manifest for the SP.
		 */
		hftest_parse_ffa_manifest(ctx, &fdt);

		/* TODO: Determine memory size referring to the SP Pkg. */
		ctx->memory_size = 1048576;
	}

	run_service_set_up(ctx, &fdt);

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

ffa_id_t hftest_get_dir_req_source_id(void)
{
	struct hftest_context *ctx = hftest_get_context();
	return ctx->dir_req_source_id;
}

void hftest_set_dir_req_source_id(ffa_id_t id)
{
	struct hftest_context *ctx = hftest_get_context();
	ctx->dir_req_source_id = id;
}
