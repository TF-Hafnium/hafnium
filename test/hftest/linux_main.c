/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hf/memiter.h"

#include "hftest_common.h"
#include "test/hftest.h"
#include <sys/reboot.h>

void test_main(int argc, const char *argv[])
{
	static const char json_command[] = "json";
	static const char run_command[] = "run";
	const char *command;

	if (argc < 2) {
		HFTEST_LOG("Unable to parse command.");
		return;
	}
	command = argv[1];

	hftest_use_registered_list();

	if (strncmp(command, json_command, sizeof(json_command)) == 0) {
		hftest_json();
		return;
	}

	if (strncmp(command, run_command, sizeof(run_command)) == 0) {
		struct memiter suite_name;
		struct memiter test_name;

		if (argc != 4) {
			HFTEST_LOG("Unable to parse test.");
			return;
		}

		memiter_init(&suite_name, argv[2], strnlen_s(argv[2], 64));
		memiter_init(&test_name, argv[3], strnlen_s(argv[3], 64));
		hftest_run(suite_name, test_name, NULL);
		return;
	}

	hftest_help();
}

int main(int argc, const char *argv[])
{
	test_main(argc, argv);
	reboot(RB_POWER_OFF);
	return 0;
}
