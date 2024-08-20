/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "hf/arch/types.h"

#include "hf/call.h"
#include "hf/dlog.h"
#include "hf/fdt.h"
#include "hf/memiter.h"
#include "hf/spinlock.h"

/*
 * Define a set up function to be run before every test in a test suite.
 */
#define SET_UP(suite) HFTEST_SET_UP(suite)

/*
 * Define a tear down function to be run after every test in a test suite.
 */
#define TEAR_DOWN(suite) HFTEST_TEAR_DOWN(suite)

/*
 * Define a test as part of a test suite.
 */
#define TEST(suite, test) HFTEST_TEST(suite, test, false, NULL)

/*
 * Define a test as part of a test suite and mark it long-running.
 */
#define TEST_LONG_RUNNING(suite, test) HFTEST_TEST(suite, test, true, NULL)

/*
 * Define a test as part of a test suite and add a precondition function.
 */
#define TEST_PRECONDITION(suite, test, precon_fn) \
	HFTEST_TEST(suite, test, false, precon_fn)

/*
 * Define a long-running test as part of a test suite and add a precondition
 * function.
 */
#define TEST_PRECONDITION_LONG_RUNNING(suite, test, precon_fn) \
	HFTEST_TEST(suite, test, true, precon_fn)

/* Define a test voluntarily skipped from the test suite. */
#define TEST_SKIP(suite, test)                       \
	static bool precon_skip_##suite_##test(void) \
	{                                            \
		return false;                        \
	}                                            \
	TEST_PRECONDITION(suite, test, precon_skip_##suite_##test)

/*
 * Define set up functions to be run during a services initialisation phase.
 * A service must partition must specify the set up functions it wishes to run
 * in the partition manifest.
 */
#define SERVICE_SET_UP(service) HFTEST_SERVICE_SET_UP(service)

/*
 * Define a test service.
 */
#define TEST_SERVICE(service) HFTEST_TEST_SERVICE(service)

/* Assertions. */
#define ASSERT_EQ(x, y) HFTEST_ASSERT_OP(x, y, ==, true)
#define ASSERT_NE(x, y) HFTEST_ASSERT_OP(x, y, !=, true)
#define ASSERT_LE(x, y) HFTEST_ASSERT_OP(x, y, <=, true)
#define ASSERT_LT(x, y) HFTEST_ASSERT_OP(x, y, <, true)
#define ASSERT_GE(x, y) HFTEST_ASSERT_OP(x, y, >=, true)
#define ASSERT_GT(x, y) HFTEST_ASSERT_OP(x, y, >, true)

#define ASSERT_STRING_EQ(x, y) HFTEST_ASSERT_STRING_OP(x, y, ==, true)
#define EXPECT_STRING_EQ(x, y) HFTEST_ASSERT_STRING_OP(x, y, ==, false)

#define ASSERT_STRING_NE(x, y) HFTEST_ASSERT_STRING_OP(x, y, !=, true)
#define EXPECT_STRING_NE(x, y) HFTEST_ASSERT_STRING_OP(x, y, !=, false)

#define ASSERT_TRUE(x) ASSERT_EQ(x, true)
#define ASSERT_FALSE(x) ASSERT_EQ(x, false)

#define EXPECT_EQ(x, y) HFTEST_ASSERT_OP(x, y, ==, false)
#define EXPECT_NE(x, y) HFTEST_ASSERT_OP(x, y, !=, false)
#define EXPECT_LE(x, y) HFTEST_ASSERT_OP(x, y, <=, false)
#define EXPECT_LT(x, y) HFTEST_ASSERT_OP(x, y, <, false)
#define EXPECT_GE(x, y) HFTEST_ASSERT_OP(x, y, >=, false)
#define EXPECT_GT(x, y) HFTEST_ASSERT_OP(x, y, >, false)

#define EXPECT_STREQ(a, b) EXPECT_EQ(strncmp(a, b, STRING_MAX_SIZE), 0)

#define EXPECT_TRUE(x) EXPECT_EQ(x, true)
#define EXPECT_FALSE(x) EXPECT_EQ(x, false)

#define FAIL(...) HFTEST_FAIL(true, __VA_ARGS__)

/* Service utilities. */
#define SERVICE_NAME_MAX_LENGTH 64
#define SERVICE_SELECT(vm_id, service, send_buffer) \
	HFTEST_SERVICE_SELECT(vm_id, service, send_buffer, 0)
#define SERVICE_SELECT_MP(vm_id, service, send_buffer, vcpu_id) \
	HFTEST_SERVICE_SELECT(vm_id, service, send_buffer, vcpu_id)

#define SERVICE_SEND_BUFFER() HFTEST_SERVICE_SEND_BUFFER()
#define SERVICE_RECV_BUFFER() HFTEST_SERVICE_RECV_BUFFER()
#define SERVICE_MEMORY_SIZE() HFTEST_SERVICE_MEMORY_SIZE()

/*
 * Prefixed to log lines from tests for easy filtering in the console.
 */
#define HFTEST_LOG_PREFIX "[hftest] "

/*
 * Indentation used e.g. to give the reason for an assertion failure.
 */
#define HFTEST_LOG_INDENT "    "

/** Initializes stage-1 MMU for tests running in a VM. */
bool hftest_mm_init(void);

/** Adds stage-1 identity mapping for pages covering bytes [base, base+size). */
void hftest_mm_identity_map(const void *base, size_t size, uint32_t mode);

bool hftest_mm_get_mode(const void *base, size_t size, uint32_t *mode);

void hftest_mm_vcpu_init(void);

/**
 * Returns a pointer to stage-1 mappings.
 * Note: There is no locking as all existing users are on the same vCPU.
 */
struct mm_stage1_locked hftest_mm_get_stage1(void);

/** Returns a pointer to the page-table pool. */
struct mpool *hftest_mm_get_ppool(void);

/**
 * Inform a host that this is the start of a test run and obtain the command
 * line arguments for it.
 */
bool hftest_ctrl_start(const struct fdt *fdt, struct memiter *cmd);

/** Inform a host that this test run has finished and clean up. */
void hftest_ctrl_finish(void);
void hftest_ctrl_reboot(void);

/** Parses and run test command */
void hftest_command(struct fdt *fdt);

/** Reboot the device. */
noreturn void hftest_device_reboot(void);

/**
 * Device-specific operation to escape from the test environment.
 * For example, an Android device with UART test controller will reboot after
 * every test run back into hftest. So as to flash the device with a different
 * system image, the device must escape this loop and boot into the Android
 * bootloader.
 * If successful, this function will not return.
 * It may not be supported on all devices.
 */
void hftest_device_exit_test_environment(void);

/**
 * Starts the CPU with the given ID. It will start at the provided entry point
 * with the provided argument. It is a wrapper around the generic cpu_start()
 * and takes care of MMU initialization.
 */
bool hftest_cpu_start(cpu_id_t id, const uint8_t *secondary_ec_stack,
		      void (*entry)(uintptr_t arg), uintptr_t arg);

cpu_id_t hftest_get_cpu_id(size_t index);

uint8_t *hftest_get_secondary_ec_stack(size_t id);

/*
 * The type of CPU entry points: a function that takes one `uintptr_t` argument
 * and returns `void`.
 */
typedef void(cpu_entry_point)(uintptr_t);

noreturn void hftest_service_main(const void *fdt_ptr);

/*
 * Return the field tracking the source of the direct request message.
 */
ffa_id_t hftest_get_dir_req_source_id(void);

/*
 * Set the field tracking the source of the direct request message.
 */
void hftest_set_dir_req_source_id(ffa_id_t id);

/* Above this point is the public API. Now include the implementation. */
#include "hftest_impl.h"

void hftest_context_init(struct hftest_context *ctx, void *send, void *recv);

void hftest_parse_ffa_manifest(struct hftest_context *ctx, struct fdt *fdt);

void hftest_map_device_regions(struct hftest_context *ctx);

void hftest_service_set_up(struct hftest_context *ctx, struct fdt *fdt);

void run_service_set_up(struct hftest_context *ctx, struct fdt *fdt);
