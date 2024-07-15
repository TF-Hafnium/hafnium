/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/semaphore.h"

void console_log_str(const char *msg)
{
	size_t len = strnlen_s(msg, STRING_MAX_SIZE);
	struct ffa_value ret = ffa_console_log_64(msg, len);
	ASSERT_EQ(ret.func, FFA_SUCCESS_32);
}

void console_log_int(uint64_t value)
{
	const char *digits = "0123456789";
	char str[64] = {0};
	char *ptr = &str[sizeof(str) - 1];
	do {
		--ptr;
		*ptr = digits[value % 10];
		value /= 10;
	} while (value);
	console_log_str(ptr);
}

#define CONSOLE_LOG1(v1) \
	(_Generic((v1), char *: console_log_str, default: console_log_int))(v1)

#define CONSOLE_LOG2(v1, v2)      \
	do {                      \
		CONSOLE_LOG1(v1); \
		CONSOLE_LOG1(v2); \
	} while (0)
#define CONSOLE_LOG3(v1, v2, v3)  \
	do {                      \
		CONSOLE_LOG1(v1); \
		CONSOLE_LOG1(v2); \
		CONSOLE_LOG1(v3); \
	} while (0)
#define CONSOLE_LOG4(v1, v2, v3, v4) \
	do {                         \
		CONSOLE_LOG1(v1);    \
		CONSOLE_LOG1(v2);    \
		CONSOLE_LOG1(v3);    \
		CONSOLE_LOG1(v4);    \
	} while (0)
#define CONSOLE_LOG5(v1, v2, v3, v4, v5) \
	do {                             \
		CONSOLE_LOG1(v1);        \
		CONSOLE_LOG1(v2);        \
		CONSOLE_LOG1(v3);        \
		CONSOLE_LOG1(v4);        \
		CONSOLE_LOG1(v5);        \
	} while (0)

struct print_args {
	struct ffa_partition_info *service_info;
	size_t num_lines;
	struct mailbox_buffers mb;
	struct semaphore sync;
	ffa_vcpu_index_t vcpu;
};

static void print_entry(uintptr_t arg)
{
	ffa_vcpu_count_t vcpu;
	size_t num_lines;

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	struct print_args *args = (struct print_args *)arg;
	ASSERT_TRUE(args != NULL);

	vcpu = args->vcpu;
	num_lines = args->num_lines;

	CONSOLE_LOG3("print: started core ", vcpu, "\n");

	for (size_t line = 0; line < num_lines; line++) {
		CONSOLE_LOG5("print: core ", vcpu, " line ", line, "\n");
	}

	CONSOLE_LOG3("print: done with core ", vcpu, "\n");

	/* Signal to primary core that test is complete.*/
	semaphore_signal(&args->sync);
	CONSOLE_LOG3("print: stopping core ", vcpu, "\n");
	arch_cpu_stop();
	CONSOLE_LOG3("unreachable: stopped core ", vcpu, "\n");
}

static void print_test(bool concurrent, size_t num_cores, size_t num_lines)
{
	struct mailbox_buffers mb_mp = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb_mp.recv);
	struct print_args args[MAX_CPUS] = {0};

	ASSERT_LE(num_cores, MAX_CPUS);

	for (size_t i = 0; i < num_cores; i++) {
		ffa_vcpu_index_t vcpu = i + 1;

		args[i] = (struct print_args){
			.service_info = service1_info,
			.vcpu = vcpu,
			.mb = mb_mp,
			.num_lines = num_lines,
		};

		semaphore_init(&args[i].sync);
		if (concurrent) {
			CONSOLE_LOG3("concurrent: starting core ", vcpu, "\n");
		} else {
			CONSOLE_LOG3("sequential: starting core ", vcpu, "\n");
		}

		ASSERT_TRUE(hftest_cpu_start(hftest_get_cpu_id(vcpu),
					     hftest_get_secondary_ec_stack(i),
					     print_entry, (uintptr_t)&args[i]));

		if (!concurrent) {
			CONSOLE_LOG3("sequential: waiting for core ", vcpu,
				     "\n");
			semaphore_wait(&args[i].sync);
			CONSOLE_LOG3("sequential: done with core ", vcpu, "\n");
		}
	}

	if (concurrent) {
		for (size_t i = 0; i < num_cores; i++) {
			ffa_vcpu_index_t vcpu = i + 1;

			CONSOLE_LOG3("concurrent: waiting for core ", vcpu,
				     "\n");
			semaphore_wait(&args[i].sync);
			CONSOLE_LOG3("concurrent: done with core ", vcpu, "\n");
		}
	}
}

TEST_PRECONDITION_LONG_RUNNING(ffa_console_log,
			       print_sequentially_4_cores_100_lines,
			       service1_is_not_vm)
{
	print_test(false, 4, 100);
}

TEST_PRECONDITION_LONG_RUNNING(ffa_console_log,
			       print_concurrently_4_cores_100_lines,
			       service1_is_not_vm)
{
	print_test(true, 4, 100);
}
