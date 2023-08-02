/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/state.h"

#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

void send_with_retry(ffa_id_t sender_vm_id, ffa_id_t target_vm_id,
		     uint32_t size)
{
	struct ffa_value res;

	do {
		res = ffa_msg_send(sender_vm_id, target_vm_id, size, 0);
	} while (res.func != FFA_SUCCESS_32);
}

/**
 * This service repeatedly takes the following steps: sets the per-CPU pointer
 * to some value, makes a hypervisor call, check that the value is still what it
 * was set to.
 *
 * This loop helps detect bugs where the hypervisor inadvertently destroys
 * state.
 *
 * At the end of its iterations, the service reports the result to the primary
 * VM, which then fails or succeeds the test.
 */
TEST_SERVICE(check_state)
{
	size_t i;
	bool ok = true;
	static volatile uintptr_t expected;
	static volatile uintptr_t actual;

	for (i = 0; i < 100000; i++) {
		/*
		 * We store the expected/actual values in volatile static
		 * variables to avoid relying on registers that may have been
		 * modified by the hypervisor.
		 */
		expected = i;
		per_cpu_ptr_set(expected);
		send_with_retry(hf_vm_get_id(), HF_PRIMARY_VM_ID, 0);
		actual = per_cpu_ptr_get();
		ok &= expected == actual;
	}

	/* Send two replies, one for each physical CPU. */
	memcpy_s(SERVICE_SEND_BUFFER(), FFA_MSG_PAYLOAD_MAX, &ok, sizeof(ok));
	send_with_retry(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(ok));
	send_with_retry(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(ok));
}
