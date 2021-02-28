/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

static void wait_for_vm(uint32_t vmid)
{
	uint16_t retry_count = 0;
	for (;;) {
		retry_count++;
		int64_t w = hf_mailbox_writable_get();
		if (w == vmid) {
			return;
		}

		if (w == -1) {
			__asm__ volatile("wfe");
		}
		/*
		 * On FVP, WFI/WFE done trap to EL2 even though SCTLR_EL2 is
		 * setup to trap these instructions. The architecture does not
		 * guarantee that these instructions will be trapped, only that
		 * it may be trapped if it does not complete in finite time. To
		 * work around this, if there are more than a threshold number
		 * of retries, simply call yiled to allow primary VM to get back
		 * control. Note that on QEMU, WFI/WFE trap just fine.
		 */
		if (retry_count > 1000) {
			ffa_yield();
			retry_count = 0;
		}
	}
}

TEST_SERVICE(echo_with_notification)
{
	/* Loop, echo messages back to the sender. */
	for (;;) {
		void *send_buf = SERVICE_SEND_BUFFER();
		void *recv_buf = SERVICE_RECV_BUFFER();
		struct ffa_value ret = ffa_msg_wait();
		ffa_vm_id_t target_vm_id = ffa_receiver(ret);
		ffa_vm_id_t source_vm_id = ffa_sender(ret);

		memcpy_s(send_buf, FFA_MSG_PAYLOAD_MAX, recv_buf,
			 ffa_msg_send_size(ret));

		while (ffa_msg_send(target_vm_id, source_vm_id,
				    ffa_msg_send_size(ret), FFA_MSG_SEND_NOTIFY)
			       .func != FFA_SUCCESS_32) {
			wait_for_vm(source_vm_id);
		}

		EXPECT_EQ(ffa_rx_release().func, FFA_SUCCESS_32);
	}
}
