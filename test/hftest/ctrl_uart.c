/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/console.h"

#include "test/hftest.h"

/* clang-format off */
#define CMD_GET_COMMAND_LINE	"[hftest_ctrl:get_command_line]\n"
#define CMD_FINISHED		"[hftest_ctrl:finished]\n"
/* clang-format on */

static char command_line[128];

static void write(const char *str)
{
	while (*str != '\0') {
		plat_console_putchar(*str);
		str++;
	}
}

static bool read(char *buf, size_t max_len, struct memiter *str)
{
	char c;
	size_t len = 0;

	while (true) {
		c = plat_console_getchar();
		if (c == '\r' || c == '\n') {
			memiter_init(str, buf, len);
			return true;
		}

		if (len < max_len) {
			buf[len++] = c;
		} else {
			return false;
		}
	}
}

bool hftest_ctrl_start(const struct fdt *fdt, struct memiter *cmd)
{
	(void)fdt;

	/* Let the console driver map its memory as device memory. */
	plat_console_mm_init(hftest_mm_get_stage1(), hftest_mm_get_ppool());

	/* Initialize the console */
	plat_console_init();

	/* Inform the host that we are ready to receive the command line. */
	write(CMD_GET_COMMAND_LINE);

	/* Read command line from the console. */
	read(command_line, ARRAY_SIZE(command_line), cmd);

	return true;
}

void hftest_ctrl_finish(void)
{
	/*
	 * Inform the host that this test has finished running and all
	 * subsequent logs belong to the next run.
	 */
	write(CMD_FINISHED);
}

void hftest_ctrl_reboot(void)
{
	/* Reboot the device. */
	hftest_device_reboot();
}
