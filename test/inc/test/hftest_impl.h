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
 * Log with the HFTEST_LOG_PREFIX and a new line. The zero is added so there is
 * always at least one variadic argument.
 */
#define HFTEST_LOG(...) HFTEST_LOG_IMPL(__VA_ARGS__, 0)
#define HFTEST_LOG_IMPL(format, ...) \
	dlog("%s" format "\n", HFTEST_LOG_PREFIX, __VA_ARGS__)

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
#define HFTEST_SET_UP(suite_name)                                   \
	static void HFTEST_SET_UP_FN(suite_name)(void);             \
	const struct hftest_test __attribute__((used))              \
	__attribute__((section(HFTEST_SET_UP_SECTION(suite_name)))) \
	HFTEST_SET_UP_STRUCT(suite_name) = {                        \
		.suite = #suite_name,                               \
		.kind = HFTEST_KIND_SET_UP,                         \
		.fn = HFTEST_SET_UP_FN(suite_name),                 \
	};                                                          \
	static void __attribute__((constructor))                    \
	HFTEST_SET_UP_CONSTRUCTOR(suite_name)(void)                 \
	{                                                           \
		hftest_register(HFTEST_SET_UP_STRUCT(suite_name));  \
	}                                                           \
	static void HFTEST_SET_UP_FN(suite_name)(void)

#define HFTEST_TEAR_DOWN(suite_name)                                   \
	static void HFTEST_TEAR_DOWN_FN(suite_name)(void);             \
	const struct hftest_test __attribute__((used))                 \
	__attribute__((section(HFTEST_TEAR_DOWN_SECTION(suite_name)))) \
	HFTEST_TEAR_DOWN_STRUCT(suite_name) = {                        \
		.suite = #suite_name,                                  \
		.kind = HFTEST_KIND_TEAR_DOWN,                         \
		.fn = HFTEST_TEAR_DOWN_FN(suite_name),                 \
	};                                                             \
	static void __attribute__((constructor))                       \
	HFTEST_TEAR_DOWN_CONSTRUCTOR(suite_name)(void)                 \
	{                                                              \
		hftest_register(HFTEST_TEAR_DOWN_STRUCT(suite_name));  \
	}                                                              \
	static void HFTEST_TEAR_DOWN_FN(suite_name)(void)

#define HFTEST_TEST(suite_name, test_name, long_running, precon_fn)          \
	static void HFTEST_TEST_FN(suite_name, test_name)(void);             \
	const struct hftest_test __attribute__((used))                       \
	__attribute__((section(HFTEST_TEST_SECTION(suite_name, test_name)))) \
	HFTEST_TEST_STRUCT(suite_name, test_name) = {                        \
		.suite = #suite_name,                                        \
		.kind = HFTEST_KIND_TEST,                                    \
		.name = #test_name,                                          \
		.is_long_running = long_running,                             \
		.fn = HFTEST_TEST_FN(suite_name, test_name),                 \
		.precondition = precon_fn,                                   \
	};                                                                   \
	static void __attribute__((constructor))                             \
	HFTEST_TEST_CONSTRUCTOR(suite_name, test_name)(void)                 \
	{                                                                    \
		hftest_register(HFTEST_TEST_STRUCT(suite_name, test_name));  \
	}                                                                    \
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

#define HFTEST_TEST_SERVICE(service_name)                              \
	static void HFTEST_SERVICE_FN(service_name)(void);             \
	const struct hftest_test __attribute__((used))                 \
	__attribute__((section(HFTEST_SERVICE_SECTION(service_name)))) \
	HFTEST_SERVICE_STRUCT(service_name) = {                        \
		.kind = HFTEST_KIND_SERVICE,                           \
		.name = #service_name,                                 \
		.fn = HFTEST_SERVICE_FN(service_name),                 \
		.precondition = NULL,                                  \
	};                                                             \
	static void HFTEST_SERVICE_FN(service_name)(void)

/* Context for tests. */
struct hftest_context {
	uint32_t failures;
	noreturn void (*abort)(void);

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
struct hftest_test {
	const char *suite;
	enum hftest_kind kind;
	const char *name;
	bool is_long_running;
	hftest_test_fn fn;
	hftest_test_precondition precondition;
};

/*
 * This union can store any of the primitive types supported by the assertion
 * macros.
 *
 * It does not include pointers as comparison of pointers is not often needed
 * and could be a mistake for string comparison. If pointer comparison is needed
 * and explicit assertion such as ASSERT_PTR_EQ() would be more appropriate.
 */
union hftest_any {
	bool b;
	char c;
	signed char sc;
	unsigned char uc;
	signed short ss;
	unsigned short us;
	signed int si;
	unsigned int ui;
	signed long int sli;
	unsigned long int uli;
	signed long long int slli;
	unsigned long long int ulli;
};

/* _Generic formatting doesn't seem to be supported so doing this manually. */
/* clang-format off */

/* Select the union member to match the type of the expression. */
#define hftest_any_get(any, x)                      \
	_Generic((x),                               \
		bool:                   (any).b,    \
		char:                   (any).c,    \
		signed char:            (any).sc,   \
		unsigned char:          (any).uc,   \
		signed short:           (any).ss,   \
		unsigned short:         (any).us,   \
		signed int:             (any).si,   \
		unsigned int:           (any).ui,   \
		signed long int:        (any).sli,  \
		unsigned long int:      (any).uli,  \
		signed long long int:   (any).slli, \
		unsigned long long int: (any).ulli)

/*
 * dlog format specifier for types. Note, these aren't the standard specifiers
 * for the types.
 */
#define hftest_dlog_format(x)                 \
	_Generic((x),                         \
		bool:                   "%u", \
		char:                   "%c", \
		signed char:            "%d", \
		unsigned char:          "%u", \
		signed short:           "%d", \
		unsigned short:         "%u", \
		signed int:             "%d", \
		unsigned int:           "%u", \
		signed long int:        "%d", \
		unsigned long int:      "%u", \
		signed long long int:   "%d", \
		unsigned long long int: "%u")

/* clang-format on */

#define HFTEST_LOG_FAILURE() \
	dlog(HFTEST_LOG_PREFIX "Failure: %s:%u\n", __FILE__, __LINE__);

#ifdef HFTEST_OPTIMIZE_FOR_SIZE
#define HFTEST_LOG_ASSERT_DETAILS(lhs, rhs, op)
#else /* HFTEST_OPTIMIZE_FOR_SIZE */
#define HFTEST_LOG_ASSERT_DETAILS(lhs, rhs, op)                              \
	dlog(HFTEST_LOG_PREFIX HFTEST_LOG_INDENT "%s %s %s (%s=", #lhs, #op, \
	     #rhs, #lhs);                                                    \
	dlog(hftest_dlog_format(lhs), hftest_any_get(lhs_value, lhs));       \
	dlog(", %s=", #rhs);                                                 \
	dlog(hftest_dlog_format(rhs), hftest_any_get(rhs_value, rhs));       \
	dlog(")\n");
#endif /* HFTEST_OPTIMIZE_FOR_SIZE */

#define HFTEST_ASSERT_OP(lhs, rhs, op, fatal)                              \
	do {                                                               \
		union hftest_any lhs_value;                                \
		union hftest_any rhs_value;                                \
		hftest_any_get(lhs_value, lhs) = (lhs);                    \
		hftest_any_get(rhs_value, rhs) = (rhs);                    \
		if (!(hftest_any_get(lhs_value, lhs)                       \
			      op hftest_any_get(rhs_value, rhs))) {        \
			struct hftest_context *ctx = hftest_get_context(); \
			++ctx->failures;                                   \
			HFTEST_LOG_FAILURE();                              \
			HFTEST_LOG_ASSERT_DETAILS(lhs, rhs, op);           \
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
#define HFTEST_SERVICE_SELECT(vm_id, service, send_buffer)                 \
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
		res = ffa_run(vm_id, 0);                                   \
		ASSERT_EQ(res.func, FFA_MSG_WAIT_32);                      \
		ASSERT_EQ(res.arg2, FFA_SLEEP_INDEFINITE);                 \
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
		res = ffa_run(vm_id, 0);                                   \
		ASSERT_EQ(res.func, FFA_YIELD_32);                         \
	} while (0)

#define HFTEST_SERVICE_SEND_BUFFER() hftest_get_context()->send
#define HFTEST_SERVICE_RECV_BUFFER() hftest_get_context()->recv
#define HFTEST_SERVICE_MEMORY_SIZE() hftest_get_context()->memory_size

void hftest_register(struct hftest_test test);
