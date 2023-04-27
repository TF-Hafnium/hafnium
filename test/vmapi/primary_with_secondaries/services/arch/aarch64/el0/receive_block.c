/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/types.h"
#include "hf/arch/vm/interrupts.h"

#include "hf/dlog.h"
#include "hf/ffa.h"

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

TEST_SERVICE(receive_block)
{
	int32_t i;
	const char message[] = "Done waiting";

	hf_interrupt_enable(EXTERNAL_INTERRUPT_ID_A, true, INTERRUPT_TYPE_IRQ);

	for (i = 0; i < 10; ++i) {
		struct ffa_value res = ffa_msg_wait();
		EXPECT_FFA_ERROR(res, FFA_INTERRUPTED);
	}

	memcpy_s(SERVICE_SEND_BUFFER(), FFA_MSG_PAYLOAD_MAX, message,
		 sizeof(message));

	ffa_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, sizeof(message), 0);
}
