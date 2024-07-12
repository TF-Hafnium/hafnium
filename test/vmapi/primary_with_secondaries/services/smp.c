/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/power_mgmt.h"

#include "hf/dlog.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "../psci.h"
#include "primary_with_secondary.h"
#include "test/hftest.h"

#define ARG_VALUE 42

/** Send a message back to the primary. */
void send_message(const char *message, uint32_t size)
{
	memcpy_s(SERVICE_SEND_BUFFER(), FFA_MSG_PAYLOAD_MAX, message, size);

	ASSERT_EQ(ffa_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, size, 0).func,
		  FFA_SUCCESS_32);
}

/**
 * Entry point of the second vCPU.
 */
static void vm_cpu_entry(uintptr_t arg)
{
	ASSERT_EQ(arg, ARG_VALUE);

	/* Check that vCPU statuses are as expected. */
	ASSERT_EQ(arch_cpu_status(0), POWER_STATUS_ON);
	ASSERT_EQ(arch_cpu_status(1), POWER_STATUS_ON);

	dlog("Secondary second vCPU started.\n");
	send_message("vCPU 1", sizeof("vCPU 1"));
	dlog("Secondary second vCPU finishing\n");
}

TEST_SERVICE(smp)
{
	/* Check that vCPU statuses are as expected. */
	ASSERT_EQ(arch_cpu_status(0), POWER_STATUS_ON);
	ASSERT_EQ(arch_cpu_status(1), POWER_STATUS_OFF);

	/* Start second vCPU. */
	dlog("Secondary starting second vCPU.\n");
	ASSERT_TRUE(hftest_cpu_start(1, hftest_get_secondary_ec_stack(0),
				     vm_cpu_entry, ARG_VALUE));
	dlog("Secondary started second vCPU.\n");

	/* Check that vCPU statuses are as expected. */
	ASSERT_EQ(arch_cpu_status(0), POWER_STATUS_ON);
	ASSERT_EQ(arch_cpu_status(1), POWER_STATUS_ON);

	send_message("vCPU 0", sizeof("vCPU 0"));
}
