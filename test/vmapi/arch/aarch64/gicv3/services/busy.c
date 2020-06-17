/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "common.h"
#include "test/hftest.h"

/*
 * Secondary VM that loops forever after receiving a message.
 */

TEST_SERVICE(busy)
{
	dlog("Secondary waiting for message...\n");
	mailbox_receive_retry();
	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	dlog("Secondary received message, looping forever.\n");
	for (;;) {
	}
}
