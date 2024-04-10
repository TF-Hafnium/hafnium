/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/assert.h"
#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#define CHARS_PER_REG UINT32_C(8)
#define REGS_PER_CALL UINT32_C(6)
#define REGS_PER_EXTENDED_CALL UINT32_C(16)
#define MAX_CHARS (CHARS_PER_REG * REGS_PER_CALL)
#define MAX_CHARS_EXTENDED (CHARS_PER_REG * REGS_PER_EXTENDED_CALL)

struct stdout_buffer {
	char chars[MAX_CHARS_EXTENDED];
	size_t len;
	bool extended;
};

static struct stdout_buffer buffers[1] = {{
	.chars = {0},
	.len = 0,
	.extended = false,
}};

void stdout_init(uint32_t ffa_version)
{
	struct stdout_buffer *buffer = &buffers[0];

	memset_s(buffer->chars, MAX_CHARS_EXTENDED, '\0', MAX_CHARS_EXTENDED);
	buffer->extended = ffa_version >= FFA_VERSION_1_2;
	buffer->len = 0;
}

void stdout_putchar(char c)
{
	struct ffa_value ret;
	struct stdout_buffer *buffer = &buffers[0];

	const size_t max_chars =
		buffer->extended ? MAX_CHARS_EXTENDED : MAX_CHARS;

	/* Write single char to buffer. */
	buffer->chars[buffer->len++] = c;

	assert(buffer->len <= max_chars);

	/*
	 * Flush buffer to stdout when buffer is full, a terminal
	 * character is reached ('\0' or '\n'), or enough characters
	 * have been buffered to fill all the registers in (extended)
	 * ffa_console_log_64.
	 */
	if (buffer->len == max_chars || c == '\0' || c == '\n') {
		ret = buffer->extended
			      ? ffa_console_log_64_extended(buffer->chars,
							    buffer->len)
			      : ffa_console_log_64(buffer->chars, buffer->len);
		assert(ret.func == FFA_SUCCESS_32);
		buffer->len = 0;
	}
}

void stdout_flush(void)
{
	struct stdout_buffer *buffer = &buffers[0];

	/* Skip flushing if buffer is empty. */
	if (buffer->len > 0) {
		stdout_putchar('\0');
	}
}
