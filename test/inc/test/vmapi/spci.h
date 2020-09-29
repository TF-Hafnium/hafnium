/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/spci.h"

#define EXPECT_SPCI_ERROR(value, spci_error)      \
	do {                                      \
		struct spci_value v = (value);    \
		EXPECT_EQ(v.func, SPCI_ERROR_32); \
		EXPECT_EQ(v.arg2, (spci_error));  \
	} while (0)

struct mailbox_buffers {
	void *send;
	void *recv;
};

struct mailbox_buffers set_up_mailbox(void);
