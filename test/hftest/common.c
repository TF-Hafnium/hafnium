/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "hf/boot_params.h"
#include "hf/fdt_handler.h"
#include "hf/memiter.h"
#include "hf/std.h"

#include "hftest_common.h"
#include "test/hftest.h"

#define HFTEST_CTRL_JSON_START "[hftest_ctrl:json_start]"
#define HFTEST_CTRL_JSON_END "[hftest_ctrl:json_end]"

static struct hftest_test hftest_constructed[HFTEST_MAX_TESTS];
static size_t hftest_count;
static struct hftest_test *hftest_list;

static struct hftest_context global_context;

static alignas(PAGE_SIZE) uint8_t secondary_ec_stack[MAX_CPUS][PAGE_SIZE];

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

/**
 * Adds the given test information to the global list, to be used by
 * `hftest_use_registered_list`.
 */
void hftest_register(struct hftest_test test)
{
	if (hftest_count < HFTEST_MAX_TESTS) {
		hftest_constructed[hftest_count++] = test;
	} else {
		HFTEST_FAIL(true, "Too many tests");
	}
}

/**
 * Uses the list of tests registered by `hftest_register(...)` as the ones to
 * run.
 */
void hftest_use_registered_list(void)
{
	hftest_list = hftest_constructed;
}

/**
 * Uses the given list of tests as the ones to run.
 */
void hftest_use_list(struct hftest_test list[], size_t count)
{
	hftest_list = list;
	hftest_count = count;
}

/**
 * Writes out a JSON structure describing the available tests.
 */
void hftest_json(void)
{
	const char *suite = NULL;
	size_t i;
	size_t tests_in_suite = 0;

	/* Wrap the JSON in tags for the hftest script to use. */
	HFTEST_LOG(HFTEST_CTRL_JSON_START);

	HFTEST_LOG("{");
	HFTEST_LOG("  \"suites\": [");
	for (i = 0; i < hftest_count; ++i) {
		struct hftest_test *test = &hftest_list[i];
		if (test->suite != suite) {
			/* Close out previously open suite. */
			if (tests_in_suite) {
				HFTEST_LOG("      ]");
				HFTEST_LOG("    },");
			}
			/* Move onto new suite. */
			suite = test->suite;
			tests_in_suite = 0;
			HFTEST_LOG("    {");
			HFTEST_LOG("      \"name\": \"%s\",", test->suite);
		}
		if (test->kind == HFTEST_KIND_SET_UP) {
			HFTEST_LOG("      \"setup\": true,");
		}
		if (test->kind == HFTEST_KIND_TEAR_DOWN) {
			HFTEST_LOG("      \"teardown\": true,");
		}
		if (test->kind == HFTEST_KIND_TEST) {
			/*
			 * If test has a precondition, run respective function.
			 * If it returns false, then the current setup is not
			 * meant to run the test. Hence, we must skip it.
			 */
			bool skip_test = test->precondition != NULL &&
					 !test->precondition();

			if (!tests_in_suite) {
				HFTEST_LOG("      \"tests\": [");
			}
			/*
			 * It's easier to put the comma at the start of the line
			 * than the end even though the JSON looks a bit funky.
			 */
			HFTEST_LOG("       %c{", tests_in_suite ? ',' : ' ');
			HFTEST_LOG("          \"name\": \"%s\",", test->name);
			HFTEST_LOG("          \"is_long_running\": %s,",
				   test->is_long_running ? "true" : "false");
			HFTEST_LOG("          \"skip_test\": %s",
				   skip_test ? "true" : "false");
			HFTEST_LOG("       }");
			++tests_in_suite;
		}
	}
	if (tests_in_suite) {
		HFTEST_LOG("      ]");
		HFTEST_LOG("    }");
	}
	HFTEST_LOG("  ]");
	HFTEST_LOG("}");

	/* Wrap the JSON in tags for the hftest script to use. */
	HFTEST_LOG(HFTEST_CTRL_JSON_END);
}

/**
 * Logs a failure message and shut down.
 */
noreturn void abort(void)
{
	HFTEST_LOG("FAIL");
	arch_power_off();
}

static void run_test(hftest_test_fn set_up, hftest_test_fn test,
		     hftest_test_fn tear_down, const struct fdt *fdt)
{
	/* Prepare the context. */
	struct hftest_context *ctx = hftest_get_context();
	memset_s(ctx, sizeof(*ctx), 0, sizeof(*ctx));
	ctx->abort = abort;
	ctx->fdt = fdt;

	/* Run any set up functions. */
	if (set_up) {
		set_up();
		if (ctx->failures) {
			abort();
		}
	}

	/* Run the test. */
	test();
	if (ctx->failures) {
		abort();
	}

	/* Run any tear down functions. */
	if (tear_down) {
		tear_down();
		if (ctx->failures) {
			abort();
		}
	}

	HFTEST_LOG("FINISHED");
}

/**
 * Runs the given test case.
 */
void hftest_run(struct memiter suite_name, struct memiter test_name,
		const struct fdt *fdt)
{
	size_t i;
	hftest_test_fn suite_set_up = NULL;
	hftest_test_fn suite_tear_down = NULL;

	for (i = 0; i < hftest_count; ++i) {
		struct hftest_test *test = &hftest_list[i];

		/* Check if this test is part of the suite we want. */
		if (memiter_iseq(&suite_name, test->suite)) {
			switch (test->kind) {
			/*
			 * The first entries in the suite are the set up and
			 * tear down functions.
			 */
			case HFTEST_KIND_SET_UP:
				suite_set_up = test->fn;
				break;
			case HFTEST_KIND_TEAR_DOWN:
				suite_tear_down = test->fn;
				break;
			/* Find the test. */
			case HFTEST_KIND_TEST:
				if (memiter_iseq(&test_name, test->name)) {
					run_test(suite_set_up, test->fn,
						 suite_tear_down, fdt);
					return;
				}
				break;
			default:
				/* Ignore other kinds. */
				break;
			}
		}
	}

	HFTEST_LOG("Unable to find requested tests.");
}

/**
 * Writes out usage information.
 */
void hftest_help(void)
{
	HFTEST_LOG("usage:");
	HFTEST_LOG("");
	HFTEST_LOG("  help");
	HFTEST_LOG("");
	HFTEST_LOG("    Show this help.");
	HFTEST_LOG("");
	HFTEST_LOG("  json");
	HFTEST_LOG("");
	HFTEST_LOG(
		"    Print a directory of test suites and tests in "
		"JSON "
		"format.");
	HFTEST_LOG("");
	HFTEST_LOG("  run <suite> <test>");
	HFTEST_LOG("");
	HFTEST_LOG("    Run the named test from the named test suite.");
}

void hftest_command(struct fdt *fdt)
{
	struct memiter command_line;
	struct memiter command;

	if (!hftest_ctrl_start(fdt, &command_line)) {
		HFTEST_LOG("Unable to read the command line.");
		return;
	}

	if (!memiter_parse_str(&command_line, &command)) {
		HFTEST_LOG("Unable to parse command.");
		return;
	}

	if (memiter_iseq(&command, "exit")) {
		hftest_device_exit_test_environment();
		return;
	}

	if (memiter_iseq(&command, "json")) {
		hftest_json();
		return;
	}

	if (memiter_iseq(&command, "run")) {
		struct memiter suite_name;
		struct memiter test_name;

		if (!memiter_parse_str(&command_line, &suite_name)) {
			HFTEST_LOG("Unable to parse test suite.");
			return;
		}

		if (!memiter_parse_str(&command_line, &test_name)) {
			HFTEST_LOG("Unable to parse test.");
			return;
		}
		hftest_run(suite_name, test_name, fdt);
		return;
	}

	hftest_help();
}

static uintptr_t vcpu_index_to_id(size_t index)
{
	/* For now we use indices as IDs for vCPUs. */
	return index;
}

uint8_t *hftest_get_secondary_ec_stack(size_t id)
{
	assert(id < MAX_CPUS);
	return secondary_ec_stack[id];
}

/**
 * Get the ID of the CPU with the given index.
 */
cpu_id_t hftest_get_cpu_id(size_t index)
{
	struct boot_params params;
	const struct fdt *fdt = hftest_get_context()->fdt;

	if (fdt == NULL) {
		/*
		 * We must be in a service VM, so apply the mapping that Hafnium
		 * uses for vCPU IDs.
		 */
		return vcpu_index_to_id(index);
	}

	/*
	 * VM is primary VM. Convert vCPU ids to the linear cpu id as passed to
	 * the primary VM in the FDT structure.
	 */
	index = MAX_CPUS - index;

	/* Find physical CPU ID from FDT. */
	fdt_find_cpus(fdt, params.cpu_ids, &params.cpu_count);

	return params.cpu_ids[index];
}
