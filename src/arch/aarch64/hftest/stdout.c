/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/stdout.h"

#include "vmapi/hf/call.h"

#define FFA_CONSOLE_LOG64_MAX_CHAR ((size_t)48)
#define STDOUT_BUFFER_SIZE ((size_t)4096)

static char stdout_buffer[STDOUT_BUFFER_SIZE];

void stdout_putchar(char c)
{
	static size_t buffer_head = 0;
	static size_t buffer_tail = 0;
	size_t to_write;

	/* Write single char to buffer. */
	stdout_buffer[buffer_tail++] = c;
	to_write = buffer_tail - buffer_head;

	/*
	 * Flush buffer to stdout when buffer is full, a terminal character is
	 * reached ('\0' or '\n'), or enough characters have been buffered to
	 * fill all the registers in ffa_console_log_64.
	 */
	if (buffer_tail == STDOUT_BUFFER_SIZE) {
		ffa_console_log_64((const char *)&stdout_buffer[buffer_head],
				   to_write);
		buffer_head = 0;
		buffer_tail = 0;
	} else if (to_write >= FFA_CONSOLE_LOG64_MAX_CHAR || c == '\0' ||
		   c == '\n') {
		ffa_console_log_64((const char *)&stdout_buffer[buffer_head],
				   to_write);
		buffer_head = buffer_tail;
	}
}
