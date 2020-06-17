/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/dlog.h"

#include "test/hftest.h"

/**
 * Test that logs are written to the buffer, and the rest is empty.
 */
TEST(dlog, log_buffer)
{
	const char test_string[] = "Test string\n";

	dlog(test_string);
	ASSERT_EQ(strncmp(test_string, dlog_buffer, sizeof(test_string)), 0);
	/* The \0 at the end shouldn't be counted. */
	ASSERT_EQ(dlog_buffer_offset, sizeof(test_string) - 1);
	for (int i = sizeof(test_string) - 1; i < DLOG_BUFFER_SIZE; ++i) {
		EXPECT_EQ(dlog_buffer[i], '\0');
	}
}
