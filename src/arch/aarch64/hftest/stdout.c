/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/stdout.h"

#include "hf/assert.h"

#include "vmapi/hf/call.h"

#define FFA_CONSOLE_LOG64_MAX_CHAR ((size_t)48)

static char stdout_buffer[FFA_CONSOLE_LOG64_MAX_CHAR];
static size_t buffer_char_count = 0;

void stdout_putchar(char c)
{
	/* Write single char to buffer. */
	stdout_buffer[buffer_char_count++] = c;

	assert(buffer_char_count <= FFA_CONSOLE_LOG64_MAX_CHAR);
	/*
	 * Flush buffer to stdout when buffer is full, a terminal character is
	 * reached ('\0' or '\n'), or enough characters have been buffered to
	 * fill all the registers in ffa_console_log_64.
	 */
	if (buffer_char_count == FFA_CONSOLE_LOG64_MAX_CHAR || c == '\0' ||
	    c == '\n') {
		ffa_console_log_64((const char *)stdout_buffer,
				   buffer_char_count);
		buffer_char_count = 0;
	}
}

void stdout_flush(void)
{
	/* Skip flushing if buffer is empty. */
	if (buffer_char_count > 0) {
		stdout_putchar('\0');
	}
}
