/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

#include "test/hftest.h"

/**
 * Service that waits for a message but expects never to get one.
 */
TEST_SERVICE(run_waiting)
{
	ffa_msg_wait();

	FAIL("Secondary VM was run.");
}
