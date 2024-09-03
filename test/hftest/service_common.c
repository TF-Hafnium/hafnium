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
#include "hf/stdout.h"

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "test/hftest.h"
#include "test/hftest_impl.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

static struct hftest_context global_context;

static alignas(PAGE_SIZE) uint8_t secondary_ec_stack[MAX_CPUS][PAGE_SIZE];

uint8_t *hftest_get_secondary_ec_stack(size_t id)
{
	assert(id < MAX_CPUS);
	return secondary_ec_stack[id];
}

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

static bool uint32list_has_next(const struct memiter *list)
{
	return memiter_size(list) > 0;
}

static void uint32list_get_next(struct memiter *list, uint32_t *out)
{
	uint64_t num;

	CHECK(uint32list_has_next(list));
	if (!fdt_parse_number(list, sizeof(uint32_t), &num)) {
		return;
	}

	*out = (uint32_t)num;
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
void hftest_parse_ffa_manifest(struct hftest_context *ctx, struct fdt *fdt)
{
	struct fdt_node root;
	struct fdt_node ffa_node;
	struct string mem_region_node_name = STRING_INIT("memory-regions");
	struct string dev_region_node_name = STRING_INIT("device-regions");
	struct memiter uuid;
	uint32_t uuid_word = 0;
	uint16_t j = 0;
	uint16_t i = 0;
	uint64_t number;

	CHECK(ctx != NULL);
	CHECK(fdt != NULL);

	ASSERT_TRUE(fdt_find_node(fdt, "/", &root));
	EXPECT_TRUE(fdt_is_compatible(&root, "arm,ffa-manifest-1.0"));
	ASSERT_TRUE(fdt_read_number(&root, "load-address",
				    &ctx->partition_manifest.load_addr));
	EXPECT_TRUE(fdt_read_number(&root, "ffa-version", &number));
	ctx->partition_manifest.ffa_version = number;

	EXPECT_TRUE(fdt_read_number(&root, "execution-ctx-count", &number));
	ctx->partition_manifest.execution_ctx_count = (uint16_t)number;

	EXPECT_TRUE(fdt_read_number(&root, "exception-level", &number));
	ctx->partition_manifest.run_time_el = (uint16_t)number;

	EXPECT_TRUE(fdt_read_property(&root, "uuid", &uuid));

	/* Parse UUIDs and populate uuid count.*/
	while (uint32list_has_next(&uuid) && j < PARTITION_MAX_UUIDS) {
		while (uint32list_has_next(&uuid) && i < 4) {
			uint32list_get_next(&uuid, &uuid_word);
			ctx->partition_manifest.uuids[j].uuid[i] = uuid_word;
			i++;
		}

		EXPECT_FALSE(
			ffa_uuid_is_null(&ctx->partition_manifest.uuids[j]));

		dlog_verbose("  UUID %#x-%x-%x-%x\n",
			     ctx->partition_manifest.uuids[j].uuid[0],
			     ctx->partition_manifest.uuids[j].uuid[1],
			     ctx->partition_manifest.uuids[j].uuid[2],
			     ctx->partition_manifest.uuids[j].uuid[3]);
		j++;
		i = 0;
	}

	ctx->partition_manifest.uuid_count = j;

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
				EXPECT_TRUE(fdt_read_number(
					&ffa_node,
					"load-address-relative-offset",
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

	ffa_node = root;

	/* Look for the device region node. */
	if (fdt_find_child(&ffa_node, &dev_region_node_name) &&
	    fdt_first_child(&ffa_node)) {
		uint32_t dev_region_count = 0;

		do {
			struct device_region *cur_region =
				&ctx->partition_manifest
					 .dev_regions[dev_region_count];
			EXPECT_TRUE(fdt_read_number(&ffa_node, "pages-count",
						    &number));
			cur_region->page_count = (uint32_t)number;

			if (!fdt_read_number(&ffa_node, "base-address",
					     &cur_region->base_address)) {
				EXPECT_TRUE(fdt_read_number(
					&ffa_node,
					"load-address-relative-offset",
					&number));
				cur_region->base_address =
					ctx->partition_manifest.load_addr +
					number;
			}

			EXPECT_TRUE(fdt_read_number(&ffa_node, "attributes",
						    &number));
			cur_region->attributes = (uint32_t)number;
			dev_region_count++;
		} while (fdt_next_sibling(&ffa_node));

		assert(dev_region_count < PARTITION_MAX_DEVICE_REGIONS);

		ctx->partition_manifest.dev_region_count = dev_region_count;
	}

	ctx->is_ffa_manifest_parsed = true;
}

void hftest_service_set_up(struct hftest_context *ctx, struct fdt *fdt)
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
	struct hftest_context *ctx;
	struct memiter args;
	hftest_test_fn service;
	struct ffa_value ret;
	struct fdt fdt;
	const ffa_id_t own_id = hf_vm_get_id();
	ffa_notifications_bitmap_t bitmap;
	struct ffa_partition_msg *message;
	uint32_t vcpu = get_current_vcpu_index();

	ctx = hftest_get_context();

	/* If boot vcpu, set up mailbox and intialize context abort function. */
	if (vcpu == 0) {
		struct mailbox_buffers mb;
		mb = set_up_mailbox();
		hftest_context_init(ctx, mb.send, mb.recv);
	}

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
		stdout_init(ctx->partition_manifest.ffa_version);

		/* TODO: Determine memory size referring to the SP Pkg. */
		ctx->memory_size = 1048576;
	}

	/* If boot vcpu, it means it is running in RTM_INIT. */
	if (vcpu == 0) {
		run_service_set_up(ctx, &fdt);
	}

	/* Receive the name of the service to run. */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	message = (struct ffa_partition_msg *)SERVICE_RECV_BUFFER();

	/*
	 * Expect to wake up with indirect message related to the next service
	 * to be executed.
	 */
	ret = ffa_notification_get(own_id, vcpu,
				   FFA_NOTIFICATION_FLAG_BITMAP_SPM |
					   FFA_NOTIFICATION_FLAG_BITMAP_HYP);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
	bitmap = ffa_notification_get_from_framework(ret);
	ASSERT_TRUE(is_ffa_spm_buffer_full_notification(bitmap) ||
		    is_ffa_hyp_buffer_full_notification(bitmap));
	ASSERT_EQ(own_id, ffa_rxtx_header_receiver(&message->header));

	if (ctx->is_ffa_manifest_parsed &&
	    ctx->partition_manifest.run_time_el == S_EL1) {
		ASSERT_EQ(hf_interrupt_get(), HF_NOTIFICATION_PENDING_INTID);
	}

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

void hftest_map_device_regions(struct hftest_context *ctx)
{
	struct device_region *dev_region;
	uint32_t dev_region_count;

	/*
	 * The running partition must have received and parsed its own
	 * partition manifest by now.
	 */
	if (!ctx || !ctx->is_ffa_manifest_parsed) {
		panic("Partition manifest not parsed.\n");
	}

	dev_region_count = ctx->partition_manifest.dev_region_count;

	/* Map the MMIO address space of the devices. */
	for (uint32_t i = 0; i < dev_region_count; i++) {
		dev_region = &ctx->partition_manifest.dev_regions[i];

		hftest_mm_identity_map(
			// NOLINTNEXTLINE(performance-no-int-to-ptr)
			(const void *)dev_region->base_address,
			dev_region->page_count * PAGE_SIZE,
			dev_region->attributes);
	}
}
