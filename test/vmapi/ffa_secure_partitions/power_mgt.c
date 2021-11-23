/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/spinlock.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

alignas(4096) static uint8_t secondary_ec_stack[MAX_CPUS - 1][4096];

/**
 * Releases the lock passed in.
 */
static void cpu_entry_echo(uintptr_t arg)
{
	ffa_vm_id_t own_id = hf_vm_get_id();
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	struct spinlock *lock = (struct spinlock *)arg;
	const uint32_t msg[] = {SP_ECHO_CMD, 0x1, 0x2, 0x3, 0x4};
	const ffa_vm_id_t receiver_id = HF_OTHER_WORLD_ID + 1;
	struct ffa_value res;

	res = sp_echo_cmd_send(own_id, receiver_id, msg[0], msg[1], msg[2],
			       msg[3]);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg4, msg[0]);
	EXPECT_EQ(res.arg5, msg[1]);
	EXPECT_EQ(res.arg6, msg[2]);
	EXPECT_EQ(res.arg7, msg[3]);

	sl_unlock(lock);

	arch_cpu_stop();
}

TEST(ffa_power_mgt, cpu_start)
{
	struct spinlock lock = SPINLOCK_INIT;

	/* Start secondary EC while holding lock. */
	sl_lock(&lock);

	for (uint32_t i = 0; i < MAX_CPUS - 1; i++) {
		dlog_verbose("Booting CPU %u\n", i + 1);

		EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(i + 1),
					   secondary_ec_stack[i],
					   sizeof(secondary_ec_stack[0]),
					   cpu_entry_echo, (uintptr_t)&lock),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&lock);

		dlog_verbose("Done with CPU %u\n", i + 1);
	}
}
