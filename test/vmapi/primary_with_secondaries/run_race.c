/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/power_mgmt.h"

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

struct cpu_state {
	struct mailbox_buffers *mb;
	struct spinlock run_lock;
};

/**
 * Iterates trying to run vCPU of the secondary VM. Returns when a message
 * of non-zero length is received.
 */
static bool run_loop(struct mailbox_buffers *mb)
{
	struct ffa_value run_res;
	bool ok = false;

	for (;;) {
		/* Run until it manages to schedule vCPU on this CPU. */
		do {
			run_res = ffa_run(SERVICE_VM1, 0);
		} while (run_res.func == FFA_ERROR_32 &&
			 run_res.arg2 == FFA_BUSY);

		/* Break out if we received a message with non-zero length. */
		if (run_res.func == FFA_MSG_SEND_32 &&
		    ffa_msg_send_size(run_res) != 0) {
			break;
		}

		/* Clear mailbox so that next message can be received. */
		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	}

	/* Copies the contents of the received boolean to the return value. */
	if (ffa_msg_send_size(run_res) == sizeof(ok)) {
		ok = *(bool *)mb->recv;
	}

	EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);

	return ok;
}

/**
 * This is the entry point of the additional primary VM vCPU. It just calls
 * the run loop so that two CPUs compete for the chance to run a secondary VM.
 */
static void vm_cpu_entry(uintptr_t arg)
{
	struct cpu_state *state = (struct cpu_state *)arg;

	run_loop(state->mb);
	sl_unlock(&state->run_lock);
}

TEAR_DOWN(vcpu_state)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

/**
 * This test tries to run the same secondary vCPU from two different physical
 * CPUs concurrently. The vCPU checks that the state is ok while it bounces
 * between the physical CPUs.
 *
 * Test is marked long-running because our implementation of spin-locks does not
 * perform well under QEMU.
 */
TEST_LONG_RUNNING(vcpu_state, concurrent_save_restore)
{
	alignas(4096) static char stack[4096];
	static struct mailbox_buffers mb;
	struct cpu_state state;

	mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "check_state", mb.send);

	/* Start second CPU. */
	state.mb = &mb;
	state.run_lock = SPINLOCK_INIT;
	sl_lock(&state.run_lock);
	ASSERT_TRUE(hftest_cpu_start(hftest_get_cpu_id(1), stack, sizeof(stack),
				     vm_cpu_entry, (uintptr_t)&state));

	/* Run on a loop until the secondary VM is done. */
	EXPECT_TRUE(run_loop(&mb));

	/*
	 * Wait for the second CPU to release its runlock to show it has
	 * finished handling messages so the RX buffer is not idle.
	 */
	sl_lock(&state.run_lock);
}
