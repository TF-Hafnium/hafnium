/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdnoreturn.h>

#include "hf/fdt.h"
#include "hf/ffa.h"
#include "hf/ffa_partition_manifest.h"
#include "hf/std.h"

#include "vmapi/hf/ffa.h"

#define HFTEST_MAX_TESTS 50

/*
 * Log with the HFTEST_LOG_PREFIX and a new line. The newline is passed as
 * an argument so there is always at least one variadic argument.
 */
#define HFTEST_LOG(...) HFTEST_LOG_IMPL(__VA_ARGS__, "\n")
#define HFTEST_LOG_IMPL(format, ...) \
	dlog(HFTEST_LOG_PREFIX format "%s", __VA_ARGS__)

/* Helper to wrap the argument in quotes. */
#define HFTEST_STR(str) #str

/*
 * Sections are names such that when the linker sorts them, all entries for the
 * same test suite are contiguous and the set up and tear down entries come
 * before the tests. This order simplifies test discovery in the running image.
 */
#define HFTEST_SET_UP_SECTION(suite_name) \
	HFTEST_STR(.hftest.suite.suite_name .1set_up)
#define HFTEST_TEAR_DOWN_SECTION(suite_name) \
	HFTEST_STR(.hftest.suite.suite_name .1tear_down)
#define HFTEST_TEST_SECTION(suite_name, test_name) \
	HFTEST_STR(.hftest.suite.suite_name .2test.test_name)
#define HFTEST_SERVICE_SET_UP_SECTION(service_name) \
	HFTEST_STR(.hftest.service_set_up.service_name)
#define HFTEST_SERVICE_SECTION(service_name) \
	HFTEST_STR(.hftest.service.service_name)

/* Helpers to construct unique identifiers. */
#define HFTEST_SET_UP_STRUCT(suite_name) hftest_set_up_##suite_name
#define HFTEST_TEAR_DOWN_STRUCT(suite_name) hftest_tear_down_##suite_name
#define HFTEST_TEST_STRUCT(suite_name, test_name) \
	hftest_test_##suite_name##_##test_name
#define HFTEST_SERVICE_SET_UP_STRUCT(service_name) \
	hftest_service_set_up_##service_name
#define HFTEST_SERVICE_STRUCT(service_name) hftest_service_##service_name

#define HFTEST_SET_UP_FN(suite_name) hftest_set_up_fn_##suite_name
#define HFTEST_TEAR_DOWN_FN(suite_name) hftest_tear_down_fn_##suite_name
#define HFTEST_TEST_FN(suite_name, test_name) \
	hftest_test_fn_##suite_name##_##test_name
#define HFTEST_SERVICE_SET_UP_FN(service_name) \
	hftest_service_set_up_fn_##service_name
#define HFTEST_SERVICE_FN(service_name) hftest_service_fn_##service_name

#define HFTEST_SET_UP_CONSTRUCTOR(suite_name) hftest_set_up_ctor_##suite_name
#define HFTEST_TEAR_DOWN_CONSTRUCTOR(suite_name) \
	hftest_tear_down_ctor_##suite_name
#define HFTEST_TEST_CONSTRUCTOR(suite_name, test_name) \
	hftest_test_ctor_##suite_name##_##test_name

/* Register test functions. */
#define HFTEST_SET_UP(suite_name)                                           \
	static void HFTEST_SET_UP_FN(suite_name)(void);                     \
	const struct hftest_test __attribute__((used))                      \
	__attribute__((section(HFTEST_SET_UP_SECTION(                       \
		suite_name)))) HFTEST_SET_UP_STRUCT(suite_name) = {         \
		.suite = #suite_name,                                       \
		.kind = HFTEST_KIND_SET_UP,                                 \
		.fn = HFTEST_SET_UP_FN(suite_name),                         \
	};                                                                  \
	static void __attribute__((constructor)) HFTEST_SET_UP_CONSTRUCTOR( \
		suite_name)(void)                                           \
	{                                                                   \
		hftest_register(HFTEST_SET_UP_STRUCT(suite_name));          \
	}                                                                   \
	static void HFTEST_SET_UP_FN(suite_name)(void)

#define HFTEST_TEAR_DOWN(suite_name)                                           \
	static void HFTEST_TEAR_DOWN_FN(suite_name)(void);                     \
	const struct hftest_test __attribute__((used))                         \
	__attribute__((section(HFTEST_TEAR_DOWN_SECTION(                       \
		suite_name)))) HFTEST_TEAR_DOWN_STRUCT(suite_name) = {         \
		.suite = #suite_name,                                          \
		.kind = HFTEST_KIND_TEAR_DOWN,                                 \
		.fn = HFTEST_TEAR_DOWN_FN(suite_name),                         \
	};                                                                     \
	static void __attribute__((constructor)) HFTEST_TEAR_DOWN_CONSTRUCTOR( \
		suite_name)(void)                                              \
	{                                                                      \
		hftest_register(HFTEST_TEAR_DOWN_STRUCT(suite_name));          \
	}                                                                      \
	static void HFTEST_TEAR_DOWN_FN(suite_name)(void)

#define HFTEST_TEST(suite_name, test_name, long_running, precon_fn)         \
	static void HFTEST_TEST_FN(suite_name, test_name)(void);            \
	const struct hftest_test __attribute__((used))                      \
	__attribute__((section(HFTEST_TEST_SECTION(                         \
		suite_name, test_name)))) HFTEST_TEST_STRUCT(suite_name,    \
							     test_name) = { \
		.suite = #suite_name,                                       \
		.kind = HFTEST_KIND_TEST,                                   \
		.name = #test_name,                                         \
		.is_long_running = (long_running),                          \
		.fn = HFTEST_TEST_FN(suite_name, test_name),                \
		.precondition = (precon_fn),                                \
	};                                                                  \
	static void __attribute__((constructor)) HFTEST_TEST_CONSTRUCTOR(   \
		suite_name, test_name)(void)                                \
	{                                                                   \
		hftest_register(HFTEST_TEST_STRUCT(suite_name, test_name)); \
	}                                                                   \
	static void HFTEST_TEST_FN(suite_name, test_name)(void)

#define HFTEST_SERVICE_SET_UP(service_name)                                   \
	static void HFTEST_SERVICE_SET_UP_FN(service_name)(void);             \
	const struct hftest_test __attribute__((used))                        \
	__attribute__((section(HFTEST_SERVICE_SET_UP_SECTION(service_name)))) \
	HFTEST_SERVICE_SET_UP_STRUCT(service_name) = {                        \
		.name = #service_name,                                        \
		.kind = HFTEST_KIND_SERVICE_SET_UP,                           \
		.fn = HFTEST_SERVICE_SET_UP_FN(service_name),                 \
	};                                                                    \
	static void HFTEST_SERVICE_SET_UP_FN(service_name)(void)

#define HFTEST_TEST_SERVICE(service_name)                                \
	static void HFTEST_SERVICE_FN(service_name)(void);               \
	const struct hftest_test __attribute__((used))                   \
	__attribute__((section(HFTEST_SERVICE_SECTION(                   \
		service_name)))) HFTEST_SERVICE_STRUCT(service_name) = { \
		.kind = HFTEST_KIND_SERVICE,                             \
		.name = #service_name,                                   \
		.fn = HFTEST_SERVICE_FN(service_name),                   \
		.precondition = NULL,                                    \
	};                                                               \
	static void HFTEST_SERVICE_FN(service_name)(void)

/* Context for tests. */
struct hftest_context {
	uint32_t failures;
	void (*abort)(void);

	/* These are used in primary VMs. */
	const struct fdt *fdt;
	bool is_ffa_manifest_parsed;
	struct ffa_partition_manifest partition_manifest;

	/* These are used in services. */
	void *send;
	void *recv;
	size_t memory_size;
	ffa_id_t dir_req_source_id;
};

struct hftest_context *hftest_get_context(void);

/* A test case. */
typedef void (*hftest_test_fn)(void);
typedef bool (*hftest_test_precondition)(void);

enum hftest_kind {
	HFTEST_KIND_SET_UP = 0,
	HFTEST_KIND_TEST = 1,
	HFTEST_KIND_TEAR_DOWN = 2,
	HFTEST_KIND_SERVICE_SET_UP = 3,
	HFTEST_KIND_SERVICE = 4,
};

/**
 * The .hftest section contains an array of this struct which describes the test
 * functions contained in the image allowing the image to inspect the tests it
 * contains.
 */
/* NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding) */
struct hftest_test {
	const char *suite;
	enum hftest_kind kind;
	const char *name;
	bool is_long_running;
	hftest_test_fn fn;
	hftest_test_precondition precondition;
};

/* _Generic formatting doesn't seem to be supported so doing this manually. */
/* clang-format off */
#define HFTEST_LOG_FAILURE() \
	dlog(HFTEST_LOG_PREFIX "Failure: %s:%u\n", __FILE__, __LINE__);

#ifdef HFTEST_OPTIMIZE_FOR_SIZE
#define HFTEST_LOG_ASSERT_DETAILS(lhs, rhs, op)
#else /* HFTEST_OPTIMIZE_FOR_SIZE */
#define HFTEST_LOG_ASSERT_DETAILS(lhs, rhs, op)                                    \
	do {                                                                           \
		dlog(HFTEST_LOG_PREFIX "assertion failed: `%s %s %s`\n", #lhs, #op, #rhs); \
		dlog(_Generic(lhs_value,                                                   \
			bool:               HFTEST_LOG_PREFIX "lhs = %hhu (%#02hhx)",          \
			char:               HFTEST_LOG_PREFIX "lhs = '%c' (%#02hhx)",          \
			signed char:        HFTEST_LOG_PREFIX "lhs = %hhd (%#02hhx)",          \
			unsigned char:      HFTEST_LOG_PREFIX "lhs = %hhu (%#02hhx)",          \
			signed short:       HFTEST_LOG_PREFIX "lhs = %hd (%#04hx)",            \
			unsigned short:     HFTEST_LOG_PREFIX "lhs = %hu (%#04hx)",            \
			signed int:         HFTEST_LOG_PREFIX "lhs = %d (%#08x)",              \
			unsigned int:       HFTEST_LOG_PREFIX "lhs = %u (%#08x)",              \
			signed long:        HFTEST_LOG_PREFIX "lhs = %ld (%#016lx)",            \
			unsigned long:      HFTEST_LOG_PREFIX "lhs = %lu (%#016lx)",            \
			signed long long:   HFTEST_LOG_PREFIX "lhs = %lld (%#016llx)",         \
			unsigned long long: HFTEST_LOG_PREFIX "lhs = %llu (%#016llx)"          \
		), lhs_value, lhs_value);                                                  \
		dlog(_Generic(rhs_value,                                                   \
			bool:               HFTEST_LOG_PREFIX "rhs = %hhu (%#02hhx)",          \
			char:               HFTEST_LOG_PREFIX "rhs = '%c' (%#02hhx)",          \
			signed char:        HFTEST_LOG_PREFIX "rhs = %hhd (%#02hhx)",          \
			unsigned char:      HFTEST_LOG_PREFIX "rhs = %hhu (%#02hhx)",          \
			signed short:       HFTEST_LOG_PREFIX "rhs = %hd (%#04hx)",            \
			unsigned short:     HFTEST_LOG_PREFIX "rhs = %hu (%#04hx)",            \
			signed int:         HFTEST_LOG_PREFIX "rhs = %d (%#08x)",              \
			unsigned int:       HFTEST_LOG_PREFIX "rhs = %u (%#08x)",              \
			signed long:        HFTEST_LOG_PREFIX "rhs = %ld (%#016lx)",            \
			unsigned long:      HFTEST_LOG_PREFIX "rhs = %lu (%#016lx)",            \
			signed long long:   HFTEST_LOG_PREFIX "rhs = %lld (%#016llx)",         \
			unsigned long long: HFTEST_LOG_PREFIX "rhs = %llu (%#016llx)"          \
		), rhs_value, rhs_value);                                                  \
	} while (0)
#endif /* HFTEST_OPTIMIZE_FOR_SIZE */
/* clang-format on */

#ifdef HFTEST_OPTIMIZE_FOR_SIZE
#define HFTEST_LOG_ASSERT_STRING_DETAILS(lhs, rhs, op)
#else /* HFTEST_OPTIMIZE_FOR_SIZE */
#define HFTEST_LOG_ASSERT_STRING_DETAILS(lhs, rhs, op)                         \
	do {                                                                   \
		dlog(HFTEST_LOG_PREFIX "assertion failed: `%s %s %s`\n", #lhs, \
		     #op, #rhs);                                               \
		dlog(HFTEST_LOG_PREFIX "lhs = \"%s\"\n", lhs_value);           \
		dlog(HFTEST_LOG_PREFIX "rhs = \"%s\"\n", rhs_value);           \
		dlog("\n");                                                    \
	} while (0)

#endif /* HFTEST_OPTIMIZE_FOR_SIZE */

#define HFTEST_ASSERT_OP(lhs, rhs, op, fatal)                              \
	do {                                                               \
		__typeof(lhs) lhs_value = lhs;                             \
		__typeof(rhs) rhs_value = rhs;                             \
		if (!(lhs_value op rhs_value)) {                           \
			struct hftest_context *ctx = hftest_get_context(); \
			++ctx->failures;                                   \
			HFTEST_LOG_FAILURE();                              \
			HFTEST_LOG_ASSERT_DETAILS(lhs, rhs, op);           \
			if (fatal) {                                       \
				ctx->abort();                              \
			}                                                  \
		}                                                          \
	} while (0)

#define HFTEST_ASSERT_STRING_OP(lhs, rhs, op, fatal)                       \
	do {                                                               \
		char *lhs_value = (lhs);                                   \
		char *rhs_value = (rhs);                                   \
		/* NOLINTNEXTLINE(bugprone-macro-parentheses) */           \
		if (!(strncmp(lhs_value, rhs_value, RSIZE_MAX) op 0)) {    \
			struct hftest_context *ctx = hftest_get_context(); \
			++ctx->failures;                                   \
			HFTEST_LOG_FAILURE();                              \
			HFTEST_LOG_ASSERT_STRING_DETAILS(lhs, rhs, op);    \
			if (fatal) {                                       \
				ctx->abort();                              \
			}                                                  \
		}                                                          \
	} while (0)

#define HFTEST_FAIL(fatal, ...)                                        \
	do {                                                           \
		struct hftest_context *ctx = hftest_get_context();     \
		++ctx->failures;                                       \
		HFTEST_LOG_FAILURE();                                  \
		dlog(HFTEST_LOG_PREFIX HFTEST_LOG_INDENT __VA_ARGS__); \
		dlog("\n");                                            \
		if (fatal) {                                           \
			ctx->abort();                                  \
		}                                                      \
	} while (0)

/**
 * Select the service to run in a service VM.
 */
#define HFTEST_SERVICE_SELECT(vm_id, service, send_buffer, vcpu_id)        \
	do {                                                               \
		struct ffa_value res;                                      \
		uint32_t msg_length =                                      \
			strnlen_s(service, SERVICE_NAME_MAX_LENGTH);       \
		struct ffa_partition_msg *message =                        \
			(struct ffa_partition_msg *)(send_buffer);         \
                                                                           \
		/*                                                         \
		 * If service is a Secondary VM, let the service configure \
		 * its mailbox and wait for a message.                     \
		 */                                                        \
		if (ffa_is_vm_id(vm_id)) {                                 \
			res = ffa_run(vm_id, vcpu_id);                     \
			ASSERT_EQ(res.func, FFA_MSG_WAIT_32);              \
			ASSERT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);         \
		}                                                          \
                                                                           \
		/*                                                         \
		 * Send the selected service to run and let it be          \
		 * handled.                                                \
		 */                                                        \
		ffa_rxtx_header_init(hf_vm_get_id(), vm_id, msg_length,    \
				     &message->header);                    \
		memcpy_s(message->payload, FFA_PARTITION_MSG_PAYLOAD_MAX,  \
			 service, msg_length);                             \
		res = ffa_msg_send2(0);                                    \
                                                                           \
		ASSERT_EQ(res.func, FFA_SUCCESS_32);                       \
		res = ffa_run(vm_id, vcpu_id);                             \
		ASSERT_EQ(res.func, FFA_YIELD_32);                         \
	} while (0)

#define HFTEST_SERVICE_SEND_BUFFER() hftest_get_context()->send
#define HFTEST_SERVICE_RECV_BUFFER() hftest_get_context()->recv
#define HFTEST_SERVICE_MEMORY_SIZE() hftest_get_context()->memory_size

void hftest_register(struct hftest_test test);
