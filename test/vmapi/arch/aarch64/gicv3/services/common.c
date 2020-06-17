/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "common.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

/**
 * Try to receive a message from the mailbox, blocking if necessary, and
 * retrying if interrupted.
 */
struct ffa_value mailbox_receive_retry(void)
{
	struct ffa_value received;

	do {
		received = ffa_msg_wait();
	} while (received.func == FFA_ERROR_32 &&
		 received.arg2 == FFA_INTERRUPTED);

	return received;
}
