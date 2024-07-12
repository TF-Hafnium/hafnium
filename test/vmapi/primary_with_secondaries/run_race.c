/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
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
			 ffa_error_code(run_res) == FFA_BUSY);

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
	/*
	 * The function prototype must match the entry function so we permit the
	 * int to pointer conversion.
	 */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
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
	static struct mailbox_buffers mb;
	struct cpu_state state;

	mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "check_state", mb.send);

	/* Start second CPU. */
	state.mb = &mb;
	state.run_lock = SPINLOCK_INIT;
	sl_lock(&state.run_lock);

	/**
	 * `hftest_get_cpu_id` function makes the assumption that cpus are
	 * specified in the FDT in reverse order and does the conversion
	 * MAX_CPUS - index internally. Since legacy VMs do not follow this
	 * convention, index 7 is passed into `hftest_cpu_get_id`.
	 */
	ASSERT_TRUE(hftest_cpu_start(hftest_get_cpu_id(7),
				     hftest_get_secondary_ec_stack(0),
				     vm_cpu_entry, (uintptr_t)&state));

	/* Run on a loop until the secondary VM is done. */
	EXPECT_TRUE(run_loop(&mb));

	/*
	 * Wait for the second CPU to release its runlock to show it has
	 * finished handling messages so the RX buffer is not idle.
	 */
	sl_lock(&state.run_lock);
}
